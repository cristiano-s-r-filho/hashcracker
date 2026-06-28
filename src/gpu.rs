use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::hash_backend::{AttackMode, HashType};

/// GPU-configuration buffer layout (mirrors WGSL `Config` struct).
///
/// This struct is mapped directly to a GPU storage buffer (binding 0)
/// shared by all WGSL kernels.
#[repr(C)]
#[derive(Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
pub struct GpuConfig {
    /// Primary target hash words (first 8)
    pub target_hash: [u32; 8],
    /// Current password length in characters
    pub password_len: u32,
    /// Total number of password candidates in this dispatch
    pub num_passwords: u32,
    /// Set to 1 by any thread that finds a match
    pub found_flag: u32,
    /// Password buffer for the match (padded to 4 u32)
    pub found_password: [u32; 4],
    /// Packed mask pattern (charset codes for each position)
    pub mask: [u32; 16],
    /// Number of active mask positions
    pub mask_len: u32,
    /// Secondary target hash words (for 128-byte digests)
    pub target_hash_extra: [u32; 8],
    /// Salt buffer (padded to 64 bytes)
    pub salt: [u32; 16],
    /// Salt length in bytes
    pub salt_len: u32,
    /// Start index for this dispatch range
    pub range_start: u32,
    /// End index for this dispatch range
    pub range_end: u32,
    /// Number of active target entries in the targets buffer
    pub num_targets: u32,
}

#[repr(C)]
#[derive(Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
struct WordEntry {
    chars: [u32; 5],
    len: u32,
}

/// A single entry in the multi-target comparison buffer on the GPU.
#[repr(C)]
#[derive(Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
pub struct TargetEntry {
    /// First 8 hash words for comparison
    pub hash: [u32; 8],
    /// Next 8 hash words (for 128-byte digest hashes)
    pub hash_extra: [u32; 8],
}

/// Data read back from the GPU after a dispatch.
pub struct ReadbackData {
    /// Number of candidates processed
    pub progress: u32,
    /// 1 if a password was found
    pub found_flag: u32,
    /// Password buffer (padded to 4 u32, 16 bytes)
    pub found_password: [u32; 4],
}

/// A GPU-accelerated cracker instance for one hash type + attack mode.
///
/// Each variant (BruteForce, Mask, Wordlist, Hybrid) owns pipeline state
/// and buffers specific to that mode.
pub enum GpuCracker {
    BruteForce {
        device: wgpu::Device,
        queue: wgpu::Queue,
        num_passwords: u32,
        password_len: u32,
        config_buf: wgpu::Buffer,
        progress_buf: wgpu::Buffer,
        staging: wgpu::Buffer,
        staging_ready: Arc<AtomicBool>,
        has_pending_readback: bool,
        target_buf: wgpu::Buffer,
        pipeline: wgpu::ComputePipeline,
        bind_group: wgpu::BindGroup,
        workgroup_x: u32,
        workgroup_y: u32,
    },
    Mask {
        device: wgpu::Device,
        queue: wgpu::Queue,
        num_passwords: u32,
        password_len: u32,
        config_buf: wgpu::Buffer,
        progress_buf: wgpu::Buffer,
        staging: wgpu::Buffer,
        staging_ready: Arc<AtomicBool>,
        has_pending_readback: bool,
        target_buf: wgpu::Buffer,
        pipeline: wgpu::ComputePipeline,
        bind_group: wgpu::BindGroup,
        workgroup_x: u32,
        workgroup_y: u32,
    },
    Wordlist {
        device: wgpu::Device,
        queue: wgpu::Queue,
        num_passwords: u32,
        words: Vec<String>,
        config_buf: wgpu::Buffer,
        progress_buf: wgpu::Buffer,
        staging: wgpu::Buffer,
        staging_ready: Arc<AtomicBool>,
        has_pending_readback: bool,
        target_buf: wgpu::Buffer,
        pipeline: wgpu::ComputePipeline,
        bind_group: wgpu::BindGroup,
        workgroup_x: u32,
        workgroup_y: u32,
    },
    Hybrid {
        device: wgpu::Device,
        queue: wgpu::Queue,
        num_passwords: u32,
        words: Vec<String>,
        config_buf: wgpu::Buffer,
        progress_buf: wgpu::Buffer,
        staging: wgpu::Buffer,
        staging_ready: Arc<AtomicBool>,
        has_pending_readback: bool,
        target_buf: wgpu::Buffer,
        pipeline: wgpu::ComputePipeline,
        bind_group: wgpu::BindGroup,
        workgroup_x: u32,
        workgroup_y: u32,
    },
}

impl GpuCracker {
    pub async fn new(hash_type: &HashType, mode: AttackMode, target_hash: [u32; 8], target_hash_extra: [u32; 8], salt: [u32; 16], salt_len: u32) -> Self {
        let num_passwords = mode.num_passwords();

        let instance = wgpu::Instance::default();
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                ..Default::default()
            })
            .await
            .expect("No GPU adapter found");

        let required_features = if hash_type.module().needs_int64() {
            wgpu::Features::SHADER_INT64
        } else {
            wgpu::Features::empty()
        };
        if !adapter.features().contains(required_features) {
            panic!("{} requires SHADER_INT64 feature (not supported by this GPU)", hash_type.name());
        }

        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: Some("hashcracker device"),
                required_features,
                ..Default::default()
            })
            .await
            .expect("Failed to create device");

        let shader_source = hash_type.shader_source(&mode);
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("crack_shader"),
            source: wgpu::ShaderSource::Wgsl(std::borrow::Cow::Borrowed(shader_source)),
        });

        let config_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("config"),
            size: std::mem::size_of::<GpuConfig>() as u64,
            usage: wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_SRC
                | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let progress_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("progress"),
            size: 4,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let staging = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("staging"),
            size: 24,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let target_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("targets"),
            size: (std::mem::size_of::<TargetEntry>() * 64) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let initial_target = TargetEntry { hash: target_hash, hash_extra: target_hash_extra };
        queue.write_buffer(&target_buf, 0, bytemuck::bytes_of(&initial_target));

        match mode {
            AttackMode::BruteForce { password_len } => {
                let config = GpuConfig {
                    target_hash,
                    password_len,
                    num_passwords,
                    found_flag: 0,
                    found_password: [0; 4],
                    mask: [0u32; 16],
                    mask_len: 0,
                    target_hash_extra,
                    salt,
                    salt_len,
                    range_start: 0,
                    range_end: num_passwords,
                    num_targets: 1,
                };

                let bgl = Self::create_bruteforce_bgl(&device);
                let pipeline = Self::create_pipeline(&device, &shader, &bgl, "bf");
                let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
                    label: Some("bf_bg"),
                    layout: &bgl,
                    entries: &[
                        wgpu::BindGroupEntry {
                            binding: 0,
                            resource: config_buf.as_entire_binding(),
                        },
                        wgpu::BindGroupEntry {
                            binding: 1,
                            resource: progress_buf.as_entire_binding(),
                        },
                        wgpu::BindGroupEntry {
                            binding: 2,
                            resource: target_buf.as_entire_binding(),
                        },
                    ],
                });

                queue.write_buffer(&config_buf, 0, bytemuck::bytes_of(&config));

                let workgroups = (num_passwords + 127) / 128;
                let wg_x = workgroups.min(65535);
                let wg_y = workgroups.div_ceil(65535);
                let mut encoder = device
                    .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                        label: Some("bf_dispatch"),
                    });
                {
                    let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                        label: Some("bf_pass"),
                        timestamp_writes: None,
                    });
                    pass.set_pipeline(&pipeline);
                    pass.set_bind_group(0, &bind_group, &[]);
                    pass.dispatch_workgroups(wg_x, wg_y, 1);
                }
                encoder.copy_buffer_to_buffer(&progress_buf, 0, &staging, 0, 4);
                encoder.copy_buffer_to_buffer(&config_buf, 40, &staging, 4, 20);
                queue.submit([encoder.finish()]);

                GpuCracker::BruteForce {
                    device,
                    queue,
                    num_passwords,
                    password_len,
                    config_buf,
                    progress_buf,
                    staging,
                    target_buf,
                    staging_ready: Arc::new(AtomicBool::new(false)),
                    has_pending_readback: false,
                    pipeline,
                    bind_group,
                    workgroup_x: wg_x,
                    workgroup_y: wg_y,
                }
            }
            AttackMode::Mask {
                mask,
                keyspace: _,
                password_len,
            } => {
                let config = GpuConfig {
                    target_hash,
                    password_len,
                    num_passwords,
                    found_flag: 0,
                    found_password: [0; 4],
                    mask,
                    mask_len: password_len,
                    target_hash_extra,
                    salt,
                    salt_len,
                    range_start: 0,
                    range_end: num_passwords,
                    num_targets: 1,
                };

                let bgl = Self::create_bruteforce_bgl(&device);
                let pipeline = Self::create_pipeline(&device, &shader, &bgl, "mask");
                let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
                    label: Some("mask_bg"),
                    layout: &bgl,
                    entries: &[
                        wgpu::BindGroupEntry {
                            binding: 0,
                            resource: config_buf.as_entire_binding(),
                        },
                        wgpu::BindGroupEntry {
                            binding: 1,
                            resource: progress_buf.as_entire_binding(),
                        },
                        wgpu::BindGroupEntry {
                            binding: 2,
                            resource: target_buf.as_entire_binding(),
                        },
                    ],
                });

                queue.write_buffer(&config_buf, 0, bytemuck::bytes_of(&config));

                let workgroups = (num_passwords + 127) / 128;
                let wg_x = workgroups.min(65535);
                let wg_y = workgroups.div_ceil(65535);
                let mut encoder = device
                    .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                        label: Some("mask_dispatch"),
                    });
                {
                    let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                        label: Some("mask_pass"),
                        timestamp_writes: None,
                    });
                    pass.set_pipeline(&pipeline);
                    pass.set_bind_group(0, &bind_group, &[]);
                    pass.dispatch_workgroups(wg_x, wg_y, 1);
                }
                encoder.copy_buffer_to_buffer(&progress_buf, 0, &staging, 0, 4);
                encoder.copy_buffer_to_buffer(&config_buf, 40, &staging, 4, 20);
                queue.submit([encoder.finish()]);

                GpuCracker::Mask {
                    device,
                    queue,
                    num_passwords,
                    password_len,
                    config_buf,
                    progress_buf,
                    staging,
                    target_buf,
                    staging_ready: Arc::new(AtomicBool::new(false)),
                    has_pending_readback: false,
                    pipeline,
                    bind_group,
                    workgroup_x: wg_x,
                    workgroup_y: wg_y,
                }
            }
            AttackMode::Wordlist { words } => {
                let config = GpuConfig {
                    target_hash,
                    password_len: 0,
                    num_passwords,
                    found_flag: 0,
                    found_password: [0; 4],
                    mask: [0u32; 16],
                    mask_len: 0,
                    target_hash_extra,
                    salt,
                    salt_len,
                range_start: 0,
                range_end: num_passwords,
                    num_targets: 1,
                };

                let entries: Vec<WordEntry> = words
                    .iter()
                    .map(|w| {
                        let bytes = w.as_bytes();
                        let len = bytes.len().min(4) as u32;
                        let mut chars = [0u32; 5];
                        for (i, &b) in bytes.iter().rev().enumerate().take(len as usize) {
                            chars[i] = b as u32;
                        }
                        chars[len as usize] = 0u32;
                        WordEntry { chars, len }
                    })
                    .collect();

                let words_buf = device.create_buffer(&wgpu::BufferDescriptor {
                    label: Some("words"),
                    size: (entries.len() as u64) * std::mem::size_of::<WordEntry>() as u64,
                    usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
                    mapped_at_creation: false,
                });

                queue.write_buffer(&words_buf, 0, bytemuck::cast_slice(&entries));
                queue.write_buffer(&config_buf, 0, bytemuck::bytes_of(&config));

                let bgl = Self::create_wordlist_bgl(&device);
                let pipeline = Self::create_pipeline(&device, &shader, &bgl, "wl");
                let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
                    label: Some("wl_bg"),
                    layout: &bgl,
                    entries: &[
                        wgpu::BindGroupEntry {
                            binding: 0,
                            resource: config_buf.as_entire_binding(),
                        },
                        wgpu::BindGroupEntry {
                            binding: 1,
                            resource: progress_buf.as_entire_binding(),
                        },
                        wgpu::BindGroupEntry {
                            binding: 2,
                            resource: words_buf.as_entire_binding(),
                        },
                        wgpu::BindGroupEntry {
                            binding: 3,
                            resource: target_buf.as_entire_binding(),
                        },
                    ],
                });

                let workgroups = (num_passwords + 127) / 128;
                let wg_x = workgroups.min(65535);
                let wg_y = workgroups.div_ceil(65535);
                let mut encoder = device
                    .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                        label: Some("wl_dispatch"),
                    });
                {
                    let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                        label: Some("wl_pass"),
                        timestamp_writes: None,
                    });
                    pass.set_pipeline(&pipeline);
                    pass.set_bind_group(0, &bind_group, &[]);
                    pass.dispatch_workgroups(wg_x, wg_y, 1);
                }
                encoder.copy_buffer_to_buffer(&progress_buf, 0, &staging, 0, 4);
                encoder.copy_buffer_to_buffer(&config_buf, 40, &staging, 4, 20);
                queue.submit([encoder.finish()]);
                drop(words_buf);

                GpuCracker::Wordlist {
                    device,
                    queue,
                    num_passwords,
                    words,
                    config_buf,
                    progress_buf,
                    staging,
                    target_buf,
                    staging_ready: Arc::new(AtomicBool::new(false)),
                    has_pending_readback: false,
                    pipeline,
                    bind_group,
                    workgroup_x: wg_x,
                    workgroup_y: wg_y,
                }
            }
            AttackMode::Hybrid { words, mask, keyspace: _, password_len: hybrid_pass_len, suffix } => {
                let mask_keyspace = AttackMode::mask_keyspace(&mask, hybrid_pass_len);
                let mut candidates = Vec::with_capacity(words.len() * mask_keyspace as usize);

                for word in &words {
                    for mi in 0..mask_keyspace {
                        let combined = if suffix {
                            format!("{}{}", word, AttackMode::index_to_mask_str(mi, &mask, hybrid_pass_len))
                        } else {
                            format!("{}{}", AttackMode::index_to_mask_str(mi, &mask, hybrid_pass_len), word)
                        };
                        if combined.len() <= 4 {
                            candidates.push(combined);
                        }
                    }
                }

                if candidates.is_empty() {
                    panic!("No candidates generated — all exceed 4-char limit");
                }

                let keyspace = candidates.len() as u32;
                let config = GpuConfig {
                    target_hash,
                    password_len: 0,
                    num_passwords: keyspace,
                    found_flag: 0,
                    found_password: [0; 4],
                    mask: [0u32; 16],
                    mask_len: 0,
                    target_hash_extra,
                    salt,
                    salt_len,
                range_start: 0,
                range_end: num_passwords,
                    num_targets: 1,
                };

                let entries: Vec<WordEntry> = candidates
                    .iter()
                    .map(|w| {
                        let bytes = w.as_bytes();
                        let len = bytes.len().min(4) as u32;
                        let mut chars = [0u32; 5];
                        for (i, &b) in bytes.iter().rev().enumerate().take(len as usize) {
                            chars[i] = b as u32;
                        }
                        chars[len as usize] = 0u32;
                        WordEntry { chars, len }
                    })
                    .collect();

                let words_buf = device.create_buffer(&wgpu::BufferDescriptor {
                    label: Some("hybrid_words"),
                    size: (entries.len() as u64) * std::mem::size_of::<WordEntry>() as u64,
                    usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
                    mapped_at_creation: false,
                });

                queue.write_buffer(&words_buf, 0, bytemuck::cast_slice(&entries));
                queue.write_buffer(&config_buf, 0, bytemuck::bytes_of(&config));

                let bgl = Self::create_wordlist_bgl(&device);
                let pipeline = Self::create_pipeline(&device, &shader, &bgl, "hybrid");
                let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
                    label: Some("hybrid_bg"),
                    layout: &bgl,
                    entries: &[
                        wgpu::BindGroupEntry {
                            binding: 0,
                            resource: config_buf.as_entire_binding(),
                        },
                        wgpu::BindGroupEntry {
                            binding: 1,
                            resource: progress_buf.as_entire_binding(),
                        },
                        wgpu::BindGroupEntry {
                            binding: 2,
                            resource: words_buf.as_entire_binding(),
                        },
                        wgpu::BindGroupEntry {
                            binding: 3,
                            resource: target_buf.as_entire_binding(),
                        },
                    ],
                });

                let workgroups = (keyspace + 127) / 128;
                let wg_x = workgroups.min(65535);
                let wg_y = workgroups.div_ceil(65535);
                let mut encoder = device
                    .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                        label: Some("hybrid_dispatch"),
                    });
                {
                    let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                        label: Some("hybrid_pass"),
                        timestamp_writes: None,
                    });
                    pass.set_pipeline(&pipeline);
                    pass.set_bind_group(0, &bind_group, &[]);
                    pass.dispatch_workgroups(wg_x, wg_y, 1);
                }
                encoder.copy_buffer_to_buffer(&progress_buf, 0, &staging, 0, 4);
                encoder.copy_buffer_to_buffer(&config_buf, 40, &staging, 4, 20);
                queue.submit([encoder.finish()]);
                drop(words_buf);

                GpuCracker::Hybrid {
                    device,
                    queue,
                    num_passwords: keyspace,
                    words: candidates,
                    config_buf,
                    progress_buf,
                    staging,
                    target_buf,
                    staging_ready: Arc::new(AtomicBool::new(false)),
                    has_pending_readback: false,
                    pipeline,
                    bind_group,
                    workgroup_x: wg_x,
                    workgroup_y: wg_y,
                }
            }
            AttackMode::Prince { .. } => {
                panic!("Prince mode is CPU-only and should not reach GPU dispatch");
            }
        }
    }

    fn create_bruteforce_bgl(device: &wgpu::Device) -> wgpu::BindGroupLayout {
        device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("bgl"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        })
    }

    fn create_wordlist_bgl(device: &wgpu::Device) -> wgpu::BindGroupLayout {
        device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("wl_bgl"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 3,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        })
    }

    fn create_pipeline(
        device: &wgpu::Device,
        shader: &wgpu::ShaderModule,
        bgl: &wgpu::BindGroupLayout,
        label: &str,
    ) -> wgpu::ComputePipeline {
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some(&format!("{}_pl", label)),
            bind_group_layouts: &[Some(bgl)],
            immediate_size: 0,
        });

        device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some(label),
            layout: Some(&pipeline_layout),
            module: shader,
            entry_point: Some("main"),
            cache: None,
            compilation_options: wgpu::PipelineCompilationOptions::default(),
        })
    }

    pub fn num_passwords(&self) -> u32 {
        match self {
            GpuCracker::BruteForce { num_passwords, .. }
            | GpuCracker::Mask { num_passwords, .. }
            | GpuCracker::Wordlist { num_passwords, .. }
            | GpuCracker::Hybrid { num_passwords, .. } => *num_passwords,
        }
    }

    pub fn write_targets(&mut self, entries: &[TargetEntry]) {
        let (_device, queue, config_buf, target_buf, progress_buf) = match self {
            GpuCracker::BruteForce { device, queue, config_buf, target_buf, progress_buf, .. }
            | GpuCracker::Mask { device, queue, config_buf, target_buf, progress_buf, .. }
            | GpuCracker::Wordlist { device, queue, config_buf, target_buf, progress_buf, .. }
            | GpuCracker::Hybrid { device, queue, config_buf, target_buf, progress_buf, .. } => {
                (device, queue, config_buf, target_buf, progress_buf)
            }
        };
        let count = entries.len().min(64) as u32;
        queue.write_buffer(target_buf, 0, bytemuck::cast_slice(&entries[..count as usize]));
        queue.write_buffer(config_buf, 236, bytemuck::bytes_of(&count));
        queue.write_buffer(config_buf, 40, bytemuck::bytes_of(&0u32));
        queue.write_buffer(progress_buf, 0, bytemuck::bytes_of(&0u32));
    }

    #[allow(dead_code)]
    pub fn redispatch(&mut self, target_hash: [u32; 8], target_hash_extra: [u32; 8]) {
        let _need_unmap = match self {
            GpuCracker::BruteForce { has_pending_readback, staging_ready, staging, .. }
            | GpuCracker::Mask { has_pending_readback, staging_ready, staging, .. }
            | GpuCracker::Wordlist { has_pending_readback, staging_ready, staging, .. }
            | GpuCracker::Hybrid { has_pending_readback, staging_ready, staging, .. } => {
                if *has_pending_readback {
                    if staging_ready.load(Ordering::Acquire) {
                        staging.unmap();
                        staging_ready.store(false, Ordering::Release);
                    }
                    *has_pending_readback = false;
                }
            }
        };

        let (device, queue, config_buf, progress_buf, staging, pipeline, bind_group, wg_x, wg_y, num_passwords) =
            match self {
                GpuCracker::BruteForce {
                    device, queue, config_buf, progress_buf, staging,
                    pipeline, bind_group, workgroup_x, workgroup_y, num_passwords, ..
                }
                | GpuCracker::Mask {
                    device, queue, config_buf, progress_buf, staging,
                    pipeline, bind_group, workgroup_x, workgroup_y, num_passwords, ..
                }
                | GpuCracker::Wordlist {
                    device, queue, config_buf, progress_buf, staging,
                    pipeline, bind_group, workgroup_x, workgroup_y, num_passwords, ..
                }
                | GpuCracker::Hybrid {
                    device, queue, config_buf, progress_buf, staging,
                    pipeline, bind_group, workgroup_x, workgroup_y, num_passwords, ..
                } => {
                    (device, queue, config_buf, progress_buf, staging,
                     pipeline, bind_group, workgroup_x, workgroup_y, num_passwords)
                }
            };

        queue.write_buffer(config_buf, 0, bytemuck::bytes_of(&target_hash));
        queue.write_buffer(config_buf, 128, bytemuck::bytes_of(&target_hash_extra));
        queue.write_buffer(config_buf, 40, bytemuck::bytes_of(&0u32));
        queue.write_buffer(progress_buf, 0, bytemuck::bytes_of(&0u32));
        queue.write_buffer(config_buf, 228, bytemuck::bytes_of(&0u32));
        queue.write_buffer(config_buf, 232, bytemuck::bytes_of(num_passwords));
        queue.write_buffer(config_buf, 236, bytemuck::bytes_of(&1u32));

        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("redispatch"),
        });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("redispatch_pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(pipeline);
            pass.set_bind_group(0, Some(&*bind_group), &[]);
            pass.dispatch_workgroups(*wg_x, *wg_y, 1);
        }
        encoder.copy_buffer_to_buffer(progress_buf, 0, staging, 0, 4);
        encoder.copy_buffer_to_buffer(config_buf, 40, staging, 4, 20);
        queue.submit([encoder.finish()]);
    }

    pub fn reconfig_len(&mut self, new_password_len: u32, new_num_passwords: u32) {
        {
            let (has_pending_readback, staging_ready, staging) = match self {
                GpuCracker::BruteForce { has_pending_readback, staging_ready, staging, .. } => {
                    (has_pending_readback, staging_ready, staging)
                }
                _ => panic!("reconfig_len only supported for BruteForce variant"),
            };
            if *has_pending_readback {
                if staging_ready.load(Ordering::Acquire) {
                    staging.unmap();
                    staging_ready.store(false, Ordering::Release);
                }
                *has_pending_readback = false;
            }
        }

        {
            let (num_passwords, password_len, workgroup_x, workgroup_y) = match self {
                GpuCracker::BruteForce { num_passwords, password_len, workgroup_x, workgroup_y, .. } => {
                    (num_passwords, password_len, workgroup_x, workgroup_y)
                }
                _ => unreachable!(),
            };
            *num_passwords = new_num_passwords;
            *password_len = new_password_len;
            let workgroups = (new_num_passwords + 127) / 128;
            *workgroup_x = workgroups.min(65535);
            *workgroup_y = workgroups.div_ceil(65535);
        }

        let (device, queue, config_buf, progress_buf, staging_for_dispatch, pipeline, bind_group, wg_x, wg_y) = match self {
            GpuCracker::BruteForce { device, queue, config_buf, progress_buf, staging, target_buf: _, pipeline, bind_group, workgroup_x, workgroup_y, .. } => {
                (device, queue, config_buf, progress_buf, staging, pipeline, bind_group, *workgroup_x, *workgroup_y)
            }
            _ => unreachable!(),
        };

        queue.write_buffer(config_buf, 32, bytemuck::bytes_of(&new_password_len));
        queue.write_buffer(config_buf, 36, bytemuck::bytes_of(&new_num_passwords));
        queue.write_buffer(config_buf, 40, bytemuck::bytes_of(&0u32));
        queue.write_buffer(progress_buf, 0, bytemuck::bytes_of(&0u32));

        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("reconfig"),
        });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("reconfig_pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(pipeline);
            pass.set_bind_group(0, Some(&*bind_group), &[]);
            pass.dispatch_workgroups(wg_x, wg_y, 1);
        }
        encoder.copy_buffer_to_buffer(progress_buf, 0, staging_for_dispatch, 0, 4);
        encoder.copy_buffer_to_buffer(config_buf, 40, staging_for_dispatch, 4, 20);
        queue.submit([encoder.finish()]);
    }

    pub fn redispatch_range(&mut self, range_start: u32, range_end: u32) {
        let chunk_size = range_end.saturating_sub(range_start);
        let _ = match self {
            GpuCracker::BruteForce { staging_ready, staging, .. }
            | GpuCracker::Mask { staging_ready, staging, .. }
            | GpuCracker::Wordlist { staging_ready, staging, .. }
            | GpuCracker::Hybrid { staging_ready, staging, .. } => {
                if staging_ready.load(Ordering::Acquire) {
                    staging.unmap();
                    staging_ready.store(false, Ordering::Release);
                }
            }
        };

        let wgs = match self {
            GpuCracker::BruteForce { .. } | GpuCracker::Mask { .. }
            | GpuCracker::Wordlist { .. } | GpuCracker::Hybrid { .. } => {
                128u32
            }
        };
        let workgroups = (chunk_size + wgs - 1) / wgs;
        let wg_x = workgroups.min(65535);
        let wg_y = workgroups.div_ceil(65535);

        match self {
            GpuCracker::BruteForce { workgroup_x, workgroup_y, .. }
            | GpuCracker::Mask { workgroup_x, workgroup_y, .. }
            | GpuCracker::Wordlist { workgroup_x, workgroup_y, .. }
            | GpuCracker::Hybrid { workgroup_x, workgroup_y, .. } => {
                *workgroup_x = wg_x;
                *workgroup_y = wg_y;
            }
        }

        let (device, queue, config_buf, progress_buf, staging, staging_ready, pipeline, bind_group) = match self {
            GpuCracker::BruteForce { device, queue, config_buf, progress_buf, staging, staging_ready, pipeline, bind_group, .. }
            | GpuCracker::Mask { device, queue, config_buf, progress_buf, staging, staging_ready, pipeline, bind_group, .. }
            | GpuCracker::Wordlist { device, queue, config_buf, progress_buf, staging, staging_ready, pipeline, bind_group, .. }
            | GpuCracker::Hybrid { device, queue, config_buf, progress_buf, staging, staging_ready, pipeline, bind_group, .. } => {
                (device, queue, config_buf, progress_buf, staging, staging_ready, pipeline, bind_group)
            }
        };

        queue.write_buffer(config_buf, 228, bytemuck::bytes_of(&range_start));
        queue.write_buffer(config_buf, 232, bytemuck::bytes_of(&range_end));
        queue.write_buffer(config_buf, 40, bytemuck::bytes_of(&0u32));
        queue.write_buffer(progress_buf, 0, bytemuck::bytes_of(&0u32));

        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("chunk_dispatch"),
        });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("chunk_pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(pipeline);
            pass.set_bind_group(0, Some(&*bind_group), &[]);
            pass.dispatch_workgroups(wg_x, wg_y, 1);
        }
        encoder.copy_buffer_to_buffer(progress_buf, 0, staging, 0, 4);
        encoder.copy_buffer_to_buffer(config_buf, 40, staging, 4, 20);
        queue.submit([encoder.finish()]);

        let _ = device.poll(wgpu::PollType::Poll);
        let ready = staging_ready.clone();
        staging.slice(..).map_async(wgpu::MapMode::Read, move |r| {
            r.expect("staging map failed");
            ready.store(true, Ordering::Release);
        });

        match self {
            GpuCracker::BruteForce { has_pending_readback, .. }
            | GpuCracker::Mask { has_pending_readback, .. }
            | GpuCracker::Wordlist { has_pending_readback, .. }
            | GpuCracker::Hybrid { has_pending_readback, .. } => {
                *has_pending_readback = true;
            }
        }
    }

    pub fn poll(&mut self) {
        let device = match self {
            GpuCracker::BruteForce { device, .. }
            | GpuCracker::Mask { device, .. }
            | GpuCracker::Wordlist { device, .. }
            | GpuCracker::Hybrid { device, .. } => device,
        };
        let _ = device.poll(wgpu::PollType::Poll);
    }

    pub fn try_readback(&mut self) -> Option<ReadbackData> {
        let (staging, staging_ready, has_pending_readback) = match self {
            GpuCracker::BruteForce { staging, staging_ready, has_pending_readback, .. }
            | GpuCracker::Mask { staging, staging_ready, has_pending_readback, .. }
            | GpuCracker::Wordlist { staging, staging_ready, has_pending_readback, .. }
            | GpuCracker::Hybrid { staging, staging_ready, has_pending_readback, .. } => {
                (staging, staging_ready, has_pending_readback)
            }
        };

        if *has_pending_readback && staging_ready.load(Ordering::Acquire) {
                let data = staging.slice(..).get_mapped_range();
            let result = ReadbackData {
                progress: bytemuck::pod_read_unaligned(&data[0..4]),
                found_flag: bytemuck::pod_read_unaligned(&data[4..8]),
                found_password: bytemuck::pod_read_unaligned(&data[8..24]),
            };
            drop(data);
            staging.unmap();
            staging_ready.store(false, Ordering::Release);
            *has_pending_readback = false;
            Some(result)
        } else {
            None
        }
    }

    pub fn decode_found_password(&self, data: &ReadbackData) -> Option<String> {
        match self {
            GpuCracker::BruteForce { password_len, .. }
            | GpuCracker::Mask { password_len, .. } => {
                let len = *password_len as usize;
                let mut s = String::with_capacity(len);
                for i in (0..len).rev() {
                    let c = char::from_u32(data.found_password[i]).unwrap_or('?');
                    if c != '\0' {
                        s.push(c);
                    }
                }
                Some(s)
            }
            GpuCracker::Wordlist { words, .. }
            | GpuCracker::Hybrid { words, .. } => {
                let idx = data.found_password[0] as usize;
                if idx < words.len() {
                    Some(words[idx].clone())
                } else {
                    None
                }
            }
        }
    }
}
