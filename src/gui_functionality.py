import tkinter as tk
import threading
import sniffer
import packet_unpacker
import packet_filter
import json


def set_filter(instance):
    """
    Updates the filter according to the settings set up by the user in the GUI.

    Keyword arguments:
        instance    -- the GUI instance
    """
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
    """
    Starts listening for packets. A new thread will be created with this task.
    The `start`, `clear`, `save` and `exit` buttons will be disabled until `stop` is pressed.
    The `stop` button becomes active.

    Keyword arguments:
        instance    -- the GUI instance
    """
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
    """
    Stops listening for packets. The `STOP` flag will be set in order to stop the previously created thread.
    The `start`, `clear`, `save` and `exit` buttons will become active.
    The `stop` button becomes disabled until packet sniffing begins again.

    Keyword arguments:
        instance    -- the GUI instance
    """
    instance.STOP = True
    instance.widgets['control']['buttons']['start'].config(state='normal')
    instance.widgets['control']['buttons']['clear'].config(state='normal')
    instance.widgets['control']['buttons']['save'].config(state='normal')
    instance.widgets['control']['buttons']['exit'].config(state='normal')
    instance.widgets['control']['buttons']['stop'].config(state='disabled')


def clear_array(instance):
    """
    Clears the packet array. Will also empty the packet list from the GUI.

    Keyword arguments:
        instance    -- the GUI instance
    """
    instance.packets = []
    instance.widgets['packet_list']['list'].delete(0, tk.END)


def save_array(instance):
    """
    Creates (or overwrites) the file where the packet array will be saved.
    The name of the file is specified in the dialog that calls this function.
    The packet array will be written as a json with indentation of 4 spaces.
    The saving dialog will also be closed.

    Keyword arguments:
        instance    -- the GUI instance
    """
    with open(instance.widgets['control']['buttons']['save_dialog_text'].get(1.0, tk.END).strip(), 'w+') as w:
        w.write(json.dumps(instance.packets, indent=4))
    instance.widgets['control']['buttons']['save_dialog_text'].delete(1.0, tk.END)
    instance.widgets['control']['buttons']['save_dialog'].withdraw()


def add_to_list(item, lst):
    """
    Adds an item to a list. This is visible on the GUI.

    Keyword arguments:
        item    -- the item to be added to the list
        lst     -- the list to which the item will be added
    """
    if len(item.get(1.0, tk.END).strip()) < 1:
        return
    lst.insert(0, item.get(1.0, tk.END).strip())
    item.delete(1.0, tk.END)


def del_from_list(lst):
    """
        Deletes the currently selected item from a list. This is visible on the GUI.

        Keyword arguments:
            lst     -- the list from which the item will be deleted
        """
    try:
        lst.delete(lst.curselection()[0])
    except IndexError:
        pass


def start_sniffing(instance):
    """
    Sniffs packets. A new sniffer is created, and while the flag to stop the thread is not set, it will continue
    to receive packets. The packets will be filtered using the custom filter set up by the user, and the
    packets that get through will be added to the visible GUI list.
    In the end, the sniffer will be closed.

    Keyword arguments:
        instance    -- the GUI instance
    """
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
    """
    Adds a packet to the internal list and the visible list.
    The internal list will contain the full packet, while the visual one will only contain more relevant data,
    the source and destination ports and IPs.

    Keyword arguments:
        instance    -- the GUI instance
        packet      -- the packet to be added to the list
    """
    instance.packets.insert(0, packet)
    instance.widgets['packet_list']['list'].insert(0, f'{packet["Ip_header"]["source_addr"]}:{packet["Tcp_header"]["source_port"]}'
                                                      f' --> '
                                                      f'{packet["Ip_header"]["destination_addr"]}:{packet["Tcp_header"]["destination_port"]}')


def modify_json(instance, event):
    """
    Updates the preview with the selected packet. The data from the internal array corresponding to the selected packet
    will be formatted and displayed in the preview tab of the GUI.

    Keyword arguments:
        instance    -- the GUI instance
        event       -- the double click event. it is used to have access to the list widget and the selected item
    """
    instance.update_preview(instance.packets[event.widget.curselection()[0]])
