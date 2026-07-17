from scapy.all import AsyncSniffer

sniffer = None


def start_capture(callback):

    global sniffer

    if sniffer is not None and sniffer.running:
        return

    sniffer = AsyncSniffer(
        prn=callback,
        store=False
    )

    sniffer.start()


def stop_capture():

    global sniffer

    if sniffer is not None and sniffer.running:
        sniffer.stop()
