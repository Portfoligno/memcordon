use super::*;

pub fn observation_poll_fixture(case: u8) -> io::Result<()> {
    if case == 7 || case == 8 {
        return retirement_poll_fixture(case == 8);
    }
    let (left, right) = private_pair()?;
    let mut controller = Channel::new(left, 7)?;
    let mut guardian = Channel::new(right, 7)?;
    let deadline = Instant::now() + Duration::from_secs(1);
    controller.request_observation(deadline)?;
    guardian.expect(Message::Observe, deadline)?;
    for _ in 0..2 {
        if controller.observe(Instant::now())?.is_some() || controller.sent != 1 {
            return Err(io::Error::other(
                "pending observation was duplicated or completed",
            ));
        }
    }
    if case == 3 {
        drop(guardian);
        return controller.observe(deadline).map(|_| ());
    }
    if case == 4 {
        guardian.run = 8;
    }
    guardian.send(
        Message::Status {
            raw: (case != 6).then_some(37 << 8),
            reaped: false,
        },
        deadline,
    )?;
    if case == 1 {
        controller.send(Message::Reap, deadline)?;
        guardian.expect(Message::Reap, deadline)?;
        guardian.send(
            Message::Status {
                raw: Some(37 << 8),
                reaped: true,
            },
            deadline,
        )?;
        match controller.receive(deadline)? {
            Some(Message::Status { reaped: true, .. }) => {}
            _ => {
                return Err(io::Error::other(
                    "observation consumed as reap acknowledgement",
                ));
            }
        }
    } else if case == 2 {
        controller.send(Message::Disarm, deadline)?;
        guardian.expect(Message::Disarm, deadline)?;
        guardian.send(Message::Retired, deadline)?;
        controller.expect(Message::Retired, deadline)?;
    } else if case == 5 || case == 6 {
        controller.inventory_query = Some(1);
        controller.send(
            Message::InventoryQuery {
                query: 1,
                metric: None,
            },
            deadline,
        )?;
        guardian.expect(
            Message::InventoryQuery {
                query: 1,
                metric: None,
            },
            deadline,
        )?;
        guardian.send(Message::ForceRequested { at: 123 }, deadline)?;
        let response = Message::InventoryChunk {
            query: 1,
            bytes: Vec::new(),
            finished: true,
        };
        guardian.send(response, deadline)?;
        controller.expect(
            Message::InventoryChunk {
                query: 1,
                bytes: Vec::new(),
                finished: true,
            },
            deadline,
        )?;
        if controller.force_receipt.load(Ordering::Acquire) != 123 {
            return Err(io::Error::other(
                "pending observation lost authoritative force receipt",
            ));
        }
    }
    let sent = controller.sent;
    if controller.observe(deadline)? != (case != 6).then_some(37 << 8)
        || controller.observation_pending
        || controller.sent != sent
    {
        return Err(io::Error::other("late observation result was lost"));
    }
    if case == 6 {
        controller.request_observation(deadline)?;
        guardian.expect(Message::Observe, deadline)?;
        guardian.send(
            Message::Status {
                raw: Some(37 << 8),
                reaped: false,
            },
            deadline,
        )?;
        if controller.observe(deadline)? != Some(37 << 8) {
            return Err(io::Error::other(
                "running observation prevented later exit observation",
            ));
        }
    }
    Ok(())
}

fn retirement_poll_fixture(expired: bool) -> io::Result<()> {
    let (left, right) = private_pair()?;
    let controller = Arc::new(Mutex::new(Channel::new(left, 7)?));
    let mut guardian = Channel::new(right, 7)?;
    let mut child = Child {
        pid: 1,
        slot: 0,
        status: None,
        remote: Some(Arc::clone(&controller)),
    };
    if expired {
        let error = child
            .retire(Instant::now())
            .expect_err("expired retirement accepted");
        if error.kind() != io::ErrorKind::TimedOut
            || controller.lock().unwrap().sent != 0
            || child.status.is_some()
        {
            return Err(io::Error::other(
                "expired retirement renewed a request or released custody",
            ));
        }
        return Ok(());
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    let responder = std::thread::spawn(move || -> io::Result<()> {
        guardian.expect(Message::Reap, deadline)?;
        // A valid response arrives after the former per-poll cap but inside the
        // caller's unchanged retirement budget. No child or workload is spawned.
        std::thread::sleep(Duration::from_millis(150));
        guardian.send(
            Message::Status {
                raw: Some(37 << 8),
                reaped: true,
            },
            deadline,
        )
    });
    let retirement = child.retire(deadline);
    responder
        .join()
        .map_err(|_| io::Error::other("reap responder panicked"))??;
    retirement?;
    if child.status.map(|status| status.code()) != Some(Some(37))
        || controller.lock().unwrap().sent != 1
    {
        return Err(io::Error::other(
            "retirement lost status or duplicated Reap",
        ));
    }
    Ok(())
}
