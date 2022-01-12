import tkinter as tk
import threading
import sniffer
import packet_unpacker
import packet_filter
import json


def set_filter(instance):
    if instance.filter is None:
        instance.filter = packet_filter.PacketFilter()
    else:
        instance.filter.modify(
            ipv4_only=(True if instance.widgets['control']['ipv']['ipv_val'].get() == 'IPV4' else False),
            ipv6_only=(True if instance.widgets['control']['ipv']['ipv_val'].get() == 'IPV6' else False),
            allowed_ips=instance.widgets['control']['ip_whitelist']['ip_whitelist_list'].get(0, tk.END),
            blocked_ips=instance.widgets['control']['ip_blacklist']['ip_blacklist_list'].get(0, tk.END),
            allowed_ports=instance.widgets['control']['port_whitelist']['port_whitelist_list'].get(0, tk.END),
            blocked_ports=instance.widgets['control']['port_blacklist']['port_blacklist_list'].get(0, tk.END)
        )


def start_listening(instance):
    instance.STOP = False
    set_filter(instance )
    instance.sniffer_thread = threading.Thread(target=start_sniffing, args=[instance])
    instance.sniffer_thread.start()
    instance.widgets['control']['buttons']['start'].config(state='disabled')
    instance.widgets['control']['buttons']['clear'].config(state='disabled')
    instance.widgets['control']['buttons']['save'].config(state='disabled')
    instance.widgets['control']['buttons']['exit'].config(state='disabled')
    instance.widgets['control']['buttons']['stop'].config(state='normal')


def stop_listening(instance):
    instance.STOP = True
    instance.widgets['control']['buttons']['start'].config(state='normal')
    instance.widgets['control']['buttons']['clear'].config(state='normal')
    instance.widgets['control']['buttons']['save'].config(state='normal')
    instance.widgets['control']['buttons']['exit'].config(state='normal')
    instance.widgets['control']['buttons']['stop'].config(state='disabled')


def clear_array(instance):
    instance.packets = []
    instance.widgets['packet_list']['list'].delete(0, tk.END)


def save_array(instance):
    with open(instance.widgets['control']['buttons']['save_dialog_text'].get(1.0, tk.END).strip(), 'w+') as w:
        w.write(json.dumps(instance.packets, indent=4))
    instance.widgets['control']['buttons']['save_dialog_text'].delete(1.0, tk.END)
    instance.widgets['control']['buttons']['save_dialog'].withdraw()


def add_to_list(item, lst):
    if len(item.get(1.0, tk.END).strip()) < 1:
        return
    lst.insert(0, item.get(1.0, tk.END).strip())
    item.delete(1.0, tk.END)


def del_from_list(item, lst):
    lst.delete(item.curselection()[0])


def start_sniffing(instance):
    the_sniffer = sniffer.Sniffer()
    the_sniffer.open_listener()
    try:
        while not instance.STOP:
            packet, _ = the_sniffer.sniff()
            eth, iph, tcp, http = packet_unpacker.unpack(packet)
            if iph is not None and tcp is not None:
                if instance.filter.verify(iph, tcp):
                    add_packet_to_list(instance, {
                        'Ethernet_frame': eth,
                        'Ip_header': iph,
                        'Tcp_header': tcp,
                        'Http_header': http,
                    })
    except KeyboardInterrupt:
        pass
    finally:
        the_sniffer.close()


def add_packet_to_list(instance, packet):
    instance.packets.insert(0, packet)
    instance.widgets['packet_list']['list'].insert(0, f'{packet["Ip_header"]["source_addr"]}:{packet["Tcp_header"]["source_port"]}'
                                                      f' --> '
                                                      f'{packet["Ip_header"]["destination_addr"]}:{packet["Tcp_header"]["destination_port"]}')


def modify_json(instance, event):
    instance.update_preview(instance.packets[event.widget.curselection()[0]])