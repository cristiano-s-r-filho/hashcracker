fn main() {
    pollster::block_on(async {
        let instance = wgpu::Instance::default();
        let adapter = instance.request_adapter(&wgpu::RequestAdapterOptions::default()).await.unwrap();
        println!("Name: {:?}", adapter.get_info().name);
        let features = adapter.features();
        println!("SHADER_INT64: {}", features.contains(wgpu::Features::SHADER_INT64));
        println!("All features: {:?}", features);
    });
}
