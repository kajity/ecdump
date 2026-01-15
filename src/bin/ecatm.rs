use env_logger::Env;
use ethercrab::{
    MainDevice, MainDeviceConfig, PduStorage, Timeouts,
    // error::Error,
    std::ethercat_now,
};

use std::{sync::Arc, time::Duration};

/// Maximum number of SubDevices that can be stored. This must be a power of 2 greater than 1.
const MAX_SUBDEVICES: usize = 16;
/// Maximum PDU data payload size - set this to the max PDI size or higher.
const MAX_PDU_DATA: usize = 1100;
/// Maximum number of EtherCAT frames that can be in flight at any one time.
const MAX_FRAMES: usize = 16;
/// Maximum total PDI length.
const PDI_LEN: usize = 64;

static PDU_STORAGE: PduStorage<MAX_FRAMES, MAX_PDU_DATA> = PduStorage::new();

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    let interface = std::env::args()
        .nth(1)
        .expect("Provide network interface as first argument.");

    log::info!("Starting EK1100 demo...");
    log::info!(
        "Ensure an EK1100 is the first SubDevice, with any number of modules connected after"
    );
    log::info!("Run with RUST_LOG=ethercrab=debug or =trace for debug information");

    let (tx, rx, pdu_loop) = PDU_STORAGE.try_split().expect("can only split once");

    let maindevice = Arc::new(MainDevice::new(
        pdu_loop,
        Timeouts {
            wait_loop_delay: Duration::from_millis(2),
            mailbox_response: Duration::from_millis(1000),
            ..Default::default()
        },
        MainDeviceConfig::default(),
    ));

    smol::block_on(async {
        #[cfg(target_os = "windows")]
        std::thread::spawn(move || {
            ethercrab::std::tx_rx_task_blocking(
                &interface,
                tx,
                rx,
                ethercrab::std::TxRxTaskConfig { spinloop: false },
            )
            .expect("TX/RX task")
        });
        #[cfg(not(target_os = "windows"))]
        smol::spawn(ethercrab::std::tx_rx_task(&interface, tx, rx).expect("spawn TX/RX task"))
            .detach();

        let group = maindevice
            .init_single_group::<MAX_SUBDEVICES, PDI_LEN>(ethercat_now)
            .await
            .expect("Init");

        log::info!("Discovered {} SubDevices", group.len());

        for subdevice in group.iter(&maindevice) {
            log::info!(
                "--> SubDevice {:#06x} name {}, description {}, {}",
                subdevice.configured_address(),
                subdevice.name(),
                subdevice
                    .description()
                    .await
                    .expect("Failed to read description")
                    .unwrap(),
                    // .unwrap_or(heapless::String::<128>::from_str("[no description]").unwrap()),
                subdevice.identity()
            );
        }
    });

    // let mut group = maindevice
    //     .init_single_group::<MAX_SUBDEVICES, PDI_LEN>(ethercat_now)
    //     .await
    //     .expect("Init");

    // log::info!("Discovered {} SubDevices", group.len());

    // for subdevice in group.iter(&maindevice) {
    //     // Special case: if an EL3004 module is discovered, it needs some specific config during
    //     // init to function properly
    //     if subdevice.name() == "EL3004" {
    //         log::info!("Found EL3004. Configuring...");

    //         subdevice.sdo_write(0x1c12, 0, 0u8).await?;
    //         subdevice.sdo_write(0x1c13, 0, 0u8).await?;

    //         subdevice.sdo_write(0x1c13, 1, 0x1a00u16).await?;
    //         subdevice.sdo_write(0x1c13, 2, 0x1a02u16).await?;
    //         subdevice.sdo_write(0x1c13, 3, 0x1a04u16).await?;
    //         subdevice.sdo_write(0x1c13, 4, 0x1a06u16).await?;
    //         subdevice.sdo_write(0x1c13, 0, 4u8).await?;
    //     }
    // }

    // let mut group = group.into_op(&maindevice).await.expect("PRE-OP -> OP");

    // for subdevice in group.iter(&maindevice) {
    //     let io = subdevice.io_raw();

    //     log::info!(
    //         "-> SubDevice {:#06x} {} inputs: {} bytes, outputs: {} bytes",
    //         subdevice.configured_address(),
    //         subdevice.name(),
    //         io.inputs().len(),
    //         io.outputs().len()
    //     );
    // }

    // let mut tick_interval = tokio::time::interval(Duration::from_millis(5));
    // tick_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // loop {
    //     group.tx_rx(&maindevice).await.expect("TX/RX");

    //     // Increment every output byte for every SubDevice by one
    //     for mut subdevice in group.iter(&maindevice) {
    //         let mut io = subdevice.io_raw_mut();

    //         for byte in io.outputs().iter_mut() {
    //             *byte = byte.wrapping_add(1);
    //         }
    //     }

    //     tick_interval.tick().await;
    // }
}
