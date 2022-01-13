import tkinter as tk
import json
from functools import partial
import gui_functionality as gf
import os


class GUI:
    """
    The GUI class. This class implements the entire visual interface of the http sniffer, but also handles
    the main loop of the program.

    Attributes:
        sniffer_thread  -- the thread that is currently sniffing
        filter          -- the packet filter that can be modified in the interface
        packets         -- the array of the currently caught packets
        colors          -- a dictionary of colors used in the visual interface
        widgets         -- the dictionary that holds all the widgets
        window          -- the main window

    Methods:
        start()             -- starts the program with GUI. Also initializes the filter
        init_colors()       -- initializes the color dictionary
        window_setup()      -- sets options for the main window and creates its subdivisions and widgets
        add_control()       -- creates the control part of the window, containing all the buttons to manipulate the flow of the sniffing
        add_ip_whitelist()  -- creates the subdivision and window to modify the whitelist of IPs
        add_ip_blacklist()  -- creates the subdivision and window to modify the blacklist of IPs
        add_port_whitelist()-- creates the subdivision and window to modify the whitelist of ports
        add_port_blacklist()-- creates the subdivision and window to modify the blacklist of ports
        add_list()          -- creates the list part of the window, where the packets will be shown
        add_preview()       -- creates the preview part of the window, where a whole packet can be viewed
        update_preview()    -- modifies the data in the preview part of the window
    """

    def __init__(self):
        """Initializes the sniffer thread, filter, colors, widgets and window, and then starts building the window."""
        # Sniffer Thread
        self.STOP = True
        self.sniffer_thread = None
        # Filter
        self.filter = None
        # Packets array
        self.packets = []
        # Colors
        self.colors = None
        self.init_colors()
        # Widgets
        self.widgets = {}
        self.window = tk.Tk()
        self.window_setup()

    def start(self):
        """Initializes the filter with default values and then starts the program with GUI."""
        gf.set_filter(self)
        try:
            self.window.mainloop()
        except KeyboardInterrupt:
            self.STOP = True

    def init_colors(self):
        """Initializes the color dictionary with preset values to be used throughout the interface."""
        self.colors = {
            'll_main': '#bfcfd9',
            'l_main': '#aec6d4',
            'main': '#7da4ba'
        }

    def window_setup(self):
        """
        Sets up the window, with options specific to the OS, and then starts building its subdivisions.
        First, the control part will be built, then the list part and last the preview part.
        """
        self.window.title(string='Http Sniffer')
        if os.name == 'nt':
            self.window.geometry('980x500')
        elif os.name == 'posix':
            self.window.geometry('1110x550')
        self.window.resizable(False, False)
        self.add_control()
        self.add_list()
        self.add_preview()

    def add_control(self):
        """
        Creates the control part of the window.
        This is a 8x2 grid of widgets, containing:
            `start`         -- and button that starts the sniffer
            `stop`          -- the button that stops the sniffer
            `clear`         -- the button that clears the captured packets list
            `save`          -- the button that opens a dialog to save the captured packets to the desired file
            `ip version`    -- the dropdown that allows filtering of IPV4 and IPV6 packets
            `ip whitelist`  -- the editable view of allowed IPs
            `ip blacklist`  -- the editable view of blocked IPs
            `port whitelist`-- the editable view of allowed ports
            `port blacklist`-- the editable view of blocked ports
            `exit`          -- the button that safely exits the program
        """
        self.widgets['control'] = {}
        self.widgets['control']['frame'] = tk.Frame(self.window, bg=self.colors['ll_main'])
        self.widgets['control']['buttons'] = {}
        # Start sniffing
        self.widgets['control']['buttons']['start'] = tk.Button(self.widgets['control']['frame'], text="Start")
        self.widgets['control']['buttons']['start'].grid(column=0, row=0, padx=10, pady=10)
        self.widgets['control']['buttons']['start'].config(command=partial(gf.start_listening, self))
        # Stop sniffing
        self.widgets['control']['buttons']['stop'] = tk.Button(self.widgets['control']['frame'], text="Stop")
        self.widgets['control']['buttons']['stop'].grid(column=0, row=1, padx=10, pady=10)
        self.widgets['control']['buttons']['stop'].config(command=partial(gf.stop_listening, self))
        self.widgets['control']['buttons']['stop'].config(state='disabled')
        # Clear list
        self.widgets['control']['buttons']['clear'] = tk.Button(self.widgets['control']['frame'], text="Clear")
        self.widgets['control']['buttons']['clear'].grid(column=1, row=0, padx=10, pady=10)
        self.widgets['control']['buttons']['clear'].config(command=partial(gf.clear_array, self))
        # Save list
        self.widgets['control']['buttons']['save_dialog'] = tk.Toplevel(self.widgets['control']['frame'],
                                                                        bg=self.colors['l_main'])
        self.widgets['control']['buttons']['save_dialog'].resizable(False, False)
        self.widgets['control']['buttons']['save_dialog'].title('Save data')
        self.widgets['control']['buttons']['save_dialog'].withdraw()
        self.widgets['control']['buttons']['save_dialog'].protocol("WM_DELETE_WINDOW",
                                                                   lambda: self.widgets['control']['buttons'][
                                                                       'save_dialog'].withdraw())
        self.widgets['control']['buttons']['save_dialog_label'] = tk.Label(
            self.widgets['control']['buttons']['save_dialog'],
            text='Enter the name of the file:', bg=self.colors['ll_main'])
        self.widgets['control']['buttons']['save_dialog_label'].pack(padx=10, pady=10)
        self.widgets['control']['buttons']['save_dialog_text'] = tk.Text(
            self.widgets['control']['buttons']['save_dialog'], width=25, height=1)
        self.widgets['control']['buttons']['save_dialog_text'].pack(padx=10, pady=10)
        self.widgets['control']['buttons']['save_dialog_btn'] = tk.Button(
            self.widgets['control']['buttons']['save_dialog'],
            text="Save", command=partial(gf.save_array, self))
        self.widgets['control']['buttons']['save_dialog_btn'].pack(padx=10, pady=10)
        self.widgets['control']['buttons']['save'] = tk.Button(self.widgets['control']['frame'], text="Save")
        self.widgets['control']['buttons']['save'].grid(column=1, row=1, padx=10, pady=10)
        self.widgets['control']['buttons']['save'].config(
            command=lambda: self.widgets['control']['buttons']['save_dialog'].deiconify())
        # IPV
        self.widgets['control']['ipv'] = {}
        self.widgets['control']['ipv']['ipv_label'] = tk.Label(self.widgets['control']['frame'], text='IP version',
                                                               bg=self.colors['l_main'])
        self.widgets['control']['ipv']['ipv_label'].grid(column=2, row=0)
        self.widgets['control']['ipv']['ipv_val'] = tk.StringVar(self.widgets['control']['frame'])
        self.widgets['control']['ipv']['ipv_val'].set('Both')
        self.widgets['control']['ipv']['ipv_list'] = tk.OptionMenu(self.widgets['control']['frame'],
                                                                   self.widgets['control']['ipv']['ipv_val'], 'Both',
                                                                   'IPV4', 'IPV6')
        self.widgets['control']['ipv']['ipv_list'].grid(column=2, row=1, rowspan=2, padx=3)

        self.add_ip_whitelist()
        self.add_ip_blacklist()
        self.add_port_whitelist()
        self.add_port_blacklist()

        self.widgets['control']['buttons']['exit'] = tk.Button(self.widgets['control']['frame'], text='Exit')
        self.widgets['control']['buttons']['exit'].grid(column=7, row=0, rowspan=2, padx=10, pady=10)
        self.widgets['control']['buttons']['exit'].config(command=lambda: self.window.destroy())
        self.window.protocol("WM_DELETE_WINDOW", lambda: self.safe_close())

        self.widgets['control']['frame'].grid(column=0, row=0, padx=3, ipadx=3, pady=5)

    def add_ip_whitelist(self):
        """
        Creates the IP whitelist editable view.
        It is composed of:
            the label and `modify` button   -- the initially visible part, pressing the button will
                                               open a window with the other parts
            the ip whitelist window         -- contains a list of the IPs currently whitelisted, an editable
                                               textbox to specify a new IP to be added to the list and
                                               three buttons, `add`, `delete` and `done`
        """
        self.widgets['control']['ip_whitelist'] = {}

        # Label
        self.widgets['control']['ip_whitelist']['ip_whitelist_label'] = tk.Label(self.widgets['control']['frame'],
                                                                                 text='IP whitelist',
                                                                                 bg=self.colors['l_main'])
        self.widgets['control']['ip_whitelist']['ip_whitelist_label'].grid(column=3, row=0, padx=5, pady=2)

        # Modify button
        self.widgets['control']['ip_whitelist']['ip_whitelist_modify'] = tk.Button(self.widgets['control']['frame'],
                                                                                   text="Modify")
        self.widgets['control']['ip_whitelist']['ip_whitelist_modify'].grid(column=3, row=1, padx=5, pady=2)
        self.widgets['control']['ip_whitelist']['ip_whitelist_modify'].config(
            command=lambda: self.widgets['control']['ip_whitelist']['frame'].deiconify())

        # New window
        self.widgets['control']['ip_whitelist']['frame'] = tk.Toplevel(self.widgets['control']['frame'],
                                                                       bg=self.colors['l_main'])
        self.widgets['control']['ip_whitelist']['frame'].resizable(False, False)
        self.widgets['control']['ip_whitelist']['frame'].title('IP whitelist')
        self.widgets['control']['ip_whitelist']['frame'].withdraw()
        self.widgets['control']['ip_whitelist']['frame'].protocol("WM_DELETE_WINDOW",
                                                                  lambda: self.widgets['control']['ip_whitelist'][
                                                                      'frame'].withdraw())

        # Text box for new IPs
        self.widgets['control']['ip_whitelist']['new_ip_whitelist'] = tk.Text(
            self.widgets['control']['ip_whitelist']['frame'], width=21, height=1)
        self.widgets['control']['ip_whitelist']['new_ip_whitelist'].grid(column=0, row=0, columnspan=2, padx=10,
                                                                         pady=10)

        # Frame for list
        self.widgets['control']['ip_whitelist']['ip_whitelist_list_frame'] = tk.Frame(
            self.widgets['control']['ip_whitelist']['frame'], bg=self.colors['l_main'])
        self.widgets['control']['ip_whitelist']['ip_whitelist_list_frame'].grid(column=0, row=1, columnspan=2, padx=10,
                                                                                pady=10)
        # List of IPs
        self.widgets['control']['ip_whitelist']['ip_whitelist_list'] = tk.Listbox(
            self.widgets['control']['ip_whitelist']['ip_whitelist_list_frame'], width=25)
        self.widgets['control']['ip_whitelist']['ip_whitelist_list'].pack(side=tk.LEFT, fill=tk.BOTH)

        # Add new IP button
        self.widgets['control']['ip_whitelist']['ip_whitelist_add'] = tk.Button(
            self.widgets['control']['ip_whitelist']['frame'], text="Add IP")
        self.widgets['control']['ip_whitelist']['ip_whitelist_add'].grid(column=2, row=0, padx=10, pady=10)
        self.widgets['control']['ip_whitelist']['ip_whitelist_add'].config(
            command=partial(gf.add_to_list, self.widgets['control']['ip_whitelist']['new_ip_whitelist'],
                            self.widgets['control']['ip_whitelist']['ip_whitelist_list']))

        # Delete selected IP
        self.widgets['control']['ip_whitelist']['ip_whitelist_del'] = tk.Button(
            self.widgets['control']['ip_whitelist']['frame'], text="Delete IP")
        self.widgets['control']['ip_whitelist']['ip_whitelist_del'].grid(column=2, row=1, padx=10, pady=10)
        self.widgets['control']['ip_whitelist']['ip_whitelist_del'].config(
            command=partial(gf.del_from_list, self.widgets['control']['ip_whitelist']['ip_whitelist_list']))

        # Exit window
        self.widgets['control']['ip_whitelist']['ip_whitelist_dn'] = tk.Button(
            self.widgets['control']['ip_whitelist']['frame'], text="Done")
        self.widgets['control']['ip_whitelist']['ip_whitelist_dn'].grid(column=2, row=2, padx=10, pady=10)
        self.widgets['control']['ip_whitelist']['ip_whitelist_dn'].config(
            command=lambda: self.widgets['control']['ip_whitelist']['frame'].withdraw())

        # Scrollbar for list
        self.widgets['control']['ip_whitelist']['scrollbar'] = tk.Scrollbar(
            self.widgets['control']['ip_whitelist']['ip_whitelist_list_frame'])
        self.widgets['control']['ip_whitelist']['scrollbar'].pack(side=tk.RIGHT, fill=tk.BOTH)
        self.widgets['control']['ip_whitelist']['ip_whitelist_list'].config(
            yscrollcommand=self.widgets['control']['ip_whitelist']['scrollbar'].set)
        self.widgets['control']['ip_whitelist']['scrollbar'].config(
            command=self.widgets['control']['ip_whitelist']['ip_whitelist_list'].yview)

    def add_ip_blacklist(self):
        """
        Creates the IP blacklist editable view.
        It is composed of:
            the label and `modify` button   -- the initially visible part, pressing the button will
                                               open a window with the other parts
            the ip blacklist window         -- contains a list of the IPs currently blacklisted, an editable
                                               textbox to specify a new IP to be added to the list and
                                               three buttons, `add`, `delete` and `done`
        """
        self.widgets['control']['ip_blacklist'] = {}

        # Label
        self.widgets['control']['ip_blacklist']['ip_blacklist_label'] = tk.Label(self.widgets['control']['frame'],
                                                                                 text='IP blacklist',
                                                                                 bg=self.colors['l_main'])
        self.widgets['control']['ip_blacklist']['ip_blacklist_label'].grid(column=4, row=0, padx=5, pady=2)

        # Modify button
        self.widgets['control']['ip_blacklist']['ip_blacklist_modify'] = tk.Button(self.widgets['control']['frame'],
                                                                                   text="Modify")
        self.widgets['control']['ip_blacklist']['ip_blacklist_modify'].grid(column=4, row=1, padx=5, pady=2)
        self.widgets['control']['ip_blacklist']['ip_blacklist_modify'].config(
            command=lambda: self.widgets['control']['ip_blacklist']['frame'].deiconify())

        # New window
        self.widgets['control']['ip_blacklist']['frame'] = tk.Toplevel(self.widgets['control']['frame'],
                                                                       bg=self.colors['l_main'])
        self.widgets['control']['ip_blacklist']['frame'].resizable(False, False)
        self.widgets['control']['ip_blacklist']['frame'].title('IP blacklist')
        self.widgets['control']['ip_blacklist']['frame'].withdraw()
        self.widgets['control']['ip_blacklist']['frame'].protocol("WM_DELETE_WINDOW",
                                                                  lambda: self.widgets['control']['ip_blacklist'][
                                                                      'frame'].withdraw())

        # Text box for new IPs
        self.widgets['control']['ip_blacklist']['new_ip_blacklist'] = tk.Text(
            self.widgets['control']['ip_blacklist']['frame'], width=21, height=1)
        self.widgets['control']['ip_blacklist']['new_ip_blacklist'].grid(column=0, row=0, columnspan=2, padx=10,
                                                                         pady=10)
        # Frame for list
        self.widgets['control']['ip_blacklist']['ip_blacklist_list_frame'] = tk.Frame(
            self.widgets['control']['ip_blacklist']['frame'], bg=self.colors['l_main'])
        self.widgets['control']['ip_blacklist']['ip_blacklist_list_frame'].grid(column=0, row=1, columnspan=2, padx=10,
                                                                                pady=10)
        # List of IPs
        self.widgets['control']['ip_blacklist']['ip_blacklist_list'] = tk.Listbox(
            self.widgets['control']['ip_blacklist']['ip_blacklist_list_frame'], width=25)
        self.widgets['control']['ip_blacklist']['ip_blacklist_list'].pack(side=tk.LEFT, fill=tk.BOTH)

        # Add new IP button
        self.widgets['control']['ip_blacklist']['ip_blacklist_add'] = tk.Button(
            self.widgets['control']['ip_blacklist']['frame'], text="Add IP")
        self.widgets['control']['ip_blacklist']['ip_blacklist_add'].grid(column=2, row=0, padx=10, pady=10)
        self.widgets['control']['ip_blacklist']['ip_blacklist_add'].config(
            command=partial(gf.add_to_list, self.widgets['control']['ip_blacklist']['new_ip_blacklist'],
                            self.widgets['control']['ip_blacklist']['ip_blacklist_list']))

        # Delete selected IP
        self.widgets['control']['ip_blacklist']['ip_blacklist_del'] = tk.Button(
            self.widgets['control']['ip_blacklist']['frame'], text="Delete IP")
        self.widgets['control']['ip_blacklist']['ip_blacklist_del'].grid(column=2, row=1, padx=10, pady=10)
        self.widgets['control']['ip_blacklist']['ip_blacklist_del'].config(
            command=partial(gf.del_from_list, self.widgets['control']['ip_blacklist']['ip_blacklist_list']))

        # Exit window
        self.widgets['control']['ip_blacklist']['ip_blacklist_dn'] = tk.Button(
            self.widgets['control']['ip_blacklist']['frame'], text="Done")
        self.widgets['control']['ip_blacklist']['ip_blacklist_dn'].grid(column=2, row=2, padx=10, pady=10)
        self.widgets['control']['ip_blacklist']['ip_blacklist_dn'].config(
            command=lambda: self.widgets['control']['ip_blacklist']['frame'].withdraw())

        # Scrollbar for list
        self.widgets['control']['ip_blacklist']['scrollbar'] = tk.Scrollbar(
            self.widgets['control']['ip_blacklist']['ip_blacklist_list_frame'])
        self.widgets['control']['ip_blacklist']['scrollbar'].pack(side=tk.RIGHT, fill=tk.BOTH)
        self.widgets['control']['ip_blacklist']['ip_blacklist_list'].config(
            yscrollcommand=self.widgets['control']['ip_blacklist']['scrollbar'].set)
        self.widgets['control']['ip_blacklist']['scrollbar'].config(
            command=self.widgets['control']['ip_blacklist']['ip_blacklist_list'].yview)

    def add_port_whitelist(self):
        """
        Creates the port whitelist editable view.
        It is composed of:
            the label and `modify` button   -- the initially visible part, pressing the button will
                                               open a window with the other parts
            the ip whitelist window         -- contains a list of the ports currently whitelisted, an editable
                                               textbox to specify a new port to be added to the list and
                                               three buttons, `add`, `delete` and `done`
        """
        self.widgets['control']['port_whitelist'] = {}

        # Label
        self.widgets['control']['port_whitelist']['port_whitelist_label'] = tk.Label(self.widgets['control']['frame'],
                                                                                     text='Port whitelist',
                                                                                     bg=self.colors['l_main'])
        self.widgets['control']['port_whitelist']['port_whitelist_label'].grid(column=5, row=0, padx=5, pady=2)

        # Modify button
        self.widgets['control']['port_whitelist']['port_whitelist_modify'] = tk.Button(self.widgets['control']['frame'],
                                                                                       text="Modify")
        self.widgets['control']['port_whitelist']['port_whitelist_modify'].grid(column=5, row=1, padx=5, pady=2)
        self.widgets['control']['port_whitelist']['port_whitelist_modify'].config(
            command=lambda: self.widgets['control']['port_whitelist']['frame'].deiconify())

        # New window
        self.widgets['control']['port_whitelist']['frame'] = tk.Toplevel(self.widgets['control']['frame'],
                                                                         bg=self.colors['l_main'])
        self.widgets['control']['port_whitelist']['frame'].resizable(False, False)
        self.widgets['control']['port_whitelist']['frame'].title('Port whitelist')
        self.widgets['control']['port_whitelist']['frame'].withdraw()
        self.widgets['control']['port_whitelist']['frame'].protocol("WM_DELETE_WINDOW",
                                                                    lambda: self.widgets['control']['port_whitelist'][
                                                                        'frame'].withdraw())

        # Text box for new ports
        self.widgets['control']['port_whitelist']['new_port_whitelist'] = tk.Text(
            self.widgets['control']['port_whitelist']['frame'], width=21, height=1)
        self.widgets['control']['port_whitelist']['new_port_whitelist'].grid(column=0, row=0, columnspan=2, padx=10,
                                                                             pady=10)
        # Frame for list
        self.widgets['control']['port_whitelist']['port_whitelist_list_frame'] = tk.Frame(
            self.widgets['control']['port_whitelist']['frame'], bg=self.colors['l_main'])
        self.widgets['control']['port_whitelist']['port_whitelist_list_frame'].grid(column=0, row=1, columnspan=2,
                                                                                    padx=10,
                                                                                    pady=10)
        # List of ports
        self.widgets['control']['port_whitelist']['port_whitelist_list'] = tk.Listbox(
            self.widgets['control']['port_whitelist']['port_whitelist_list_frame'], width=25)
        self.widgets['control']['port_whitelist']['port_whitelist_list'].pack(side=tk.LEFT, fill=tk.BOTH)
        self.widgets['control']['port_whitelist']['port_whitelist_list'].insert(0, '80')
        self.widgets['control']['port_whitelist']['port_whitelist_list'].insert(0, '443')

        # Add new port button
        self.widgets['control']['port_whitelist']['port_whitelist_add'] = tk.Button(
            self.widgets['control']['port_whitelist']['frame'], text="Add port")
        self.widgets['control']['port_whitelist']['port_whitelist_add'].grid(column=2, row=0, padx=10, pady=10)
        self.widgets['control']['port_whitelist']['port_whitelist_add'].config(
            command=partial(gf.add_to_list, self.widgets['control']['port_whitelist']['new_port_whitelist'],
                            self.widgets['control']['port_whitelist']['port_whitelist_list']))

        # Delete selected port
        self.widgets['control']['port_whitelist']['port_whitelist_del'] = tk.Button(
            self.widgets['control']['port_whitelist']['frame'], text="Delete port")
        self.widgets['control']['port_whitelist']['port_whitelist_del'].grid(column=2, row=1, padx=10, pady=10)
        self.widgets['control']['port_whitelist']['port_whitelist_del'].config(
            command=partial(gf.del_from_list, self.widgets['control']['port_whitelist']['port_whitelist_list']))

        # Exit window
        self.widgets['control']['port_whitelist']['port_whitelist_dn'] = tk.Button(
            self.widgets['control']['port_whitelist']['frame'], text="Done")
        self.widgets['control']['port_whitelist']['port_whitelist_dn'].grid(column=2, row=2, padx=10, pady=10)
        self.widgets['control']['port_whitelist']['port_whitelist_dn'].config(
            command=lambda: self.widgets['control']['port_whitelist']['frame'].withdraw())

        # Scrollbar for list
        self.widgets['control']['port_whitelist']['scrollbar'] = tk.Scrollbar(
            self.widgets['control']['port_whitelist']['port_whitelist_list_frame'])
        self.widgets['control']['port_whitelist']['scrollbar'].pack(side=tk.RIGHT, fill=tk.BOTH)
        self.widgets['control']['port_whitelist']['port_whitelist_list'].config(
            yscrollcommand=self.widgets['control']['port_whitelist']['scrollbar'].set)
        self.widgets['control']['port_whitelist']['scrollbar'].config(
            command=self.widgets['control']['port_whitelist']['port_whitelist_list'].yview)

    def add_port_blacklist(self):
        """
        Creates the port blacklist editable view.
        It is composed of:
            the label and `modify` button   -- the initially visible part, pressing the button will
                                               open a window with the other parts
            the ip blacklist window         -- contains a list of the ports currently blacklisted, an editable
                                               textbox to specify a new port to be added to the list and
                                               three buttons, `add`, `delete` and `done`
        """
        self.widgets['control']['port_blacklist'] = {}

        # Label
        self.widgets['control']['port_blacklist']['port_blacklist_label'] = tk.Label(self.widgets['control']['frame'],
                                                                                     text='Port blacklist',
                                                                                     bg=self.colors['l_main'])
        self.widgets['control']['port_blacklist']['port_blacklist_label'].grid(column=6, row=0, padx=5, pady=2)

        # Modify button
        self.widgets['control']['port_blacklist']['port_blacklist_modify'] = tk.Button(self.widgets['control']['frame'],
                                                                                       text="Modify")
        self.widgets['control']['port_blacklist']['port_blacklist_modify'].grid(column=6, row=1, padx=5, pady=2)
        self.widgets['control']['port_blacklist']['port_blacklist_modify'].config(
            command=lambda: self.widgets['control']['port_blacklist']['frame'].deiconify())

        # New window
        self.widgets['control']['port_blacklist']['frame'] = tk.Toplevel(self.widgets['control']['frame'],
                                                                         bg=self.colors['l_main'])
        self.widgets['control']['port_blacklist']['frame'].resizable(False, False)
        self.widgets['control']['port_blacklist']['frame'].title('Port blacklist')
        self.widgets['control']['port_blacklist']['frame'].withdraw()
        self.widgets['control']['port_blacklist']['frame'].protocol("WM_DELETE_WINDOW",
                                                                    lambda: self.widgets['control']['port_blacklist'][
                                                                        'frame'].withdraw())

        # Text box for new ports
        self.widgets['control']['port_blacklist']['new_port_blacklist'] = tk.Text(
            self.widgets['control']['port_blacklist']['frame'], width=21, height=1)
        self.widgets['control']['port_blacklist']['new_port_blacklist'].grid(column=0, row=0, columnspan=2, padx=10,
                                                                             pady=10)
        # Frame for list
        self.widgets['control']['port_blacklist']['port_blacklist_list_frame'] = tk.Frame(
            self.widgets['control']['port_blacklist']['frame'], bg=self.colors['l_main'])
        self.widgets['control']['port_blacklist']['port_blacklist_list_frame'].grid(column=0, row=1, columnspan=2,
                                                                                    padx=10,
                                                                                    pady=10)
        # List of ports
        self.widgets['control']['port_blacklist']['port_blacklist_list'] = tk.Listbox(
            self.widgets['control']['port_blacklist']['port_blacklist_list_frame'], width=25)
        self.widgets['control']['port_blacklist']['port_blacklist_list'].pack(side=tk.LEFT, fill=tk.BOTH)

        # Add new port button
        self.widgets['control']['port_blacklist']['port_blacklist_add'] = tk.Button(
            self.widgets['control']['port_blacklist']['frame'], text="Add port")
        self.widgets['control']['port_blacklist']['port_blacklist_add'].grid(column=2, row=0, padx=10, pady=10)
        self.widgets['control']['port_blacklist']['port_blacklist_add'].config(
            command=partial(gf.add_to_list, self.widgets['control']['port_blacklist']['new_port_blacklist'],
                            self.widgets['control']['port_blacklist']['port_blacklist_list']))

        # Delete selected port
        self.widgets['control']['port_blacklist']['port_blacklist_del'] = tk.Button(
            self.widgets['control']['port_blacklist']['frame'], text="Delete port")
        self.widgets['control']['port_blacklist']['port_blacklist_del'].grid(column=2, row=1, padx=10, pady=10)
        self.widgets['control']['port_blacklist']['port_blacklist_del'].config(
            command=partial(gf.del_from_list, self.widgets['control']['port_blacklist']['port_blacklist_list']))

        # Exit window
        self.widgets['control']['port_blacklist']['port_blacklist_dn'] = tk.Button(
            self.widgets['control']['port_blacklist']['frame'], text="Done")
        self.widgets['control']['port_blacklist']['port_blacklist_dn'].grid(column=2, row=2, padx=10, pady=10)
        self.widgets['control']['port_blacklist']['port_blacklist_dn'].config(
            command=lambda: self.widgets['control']['port_blacklist']['frame'].withdraw())

        # Scrollbar for list
        self.widgets['control']['port_blacklist']['scrollbar'] = tk.Scrollbar(
            self.widgets['control']['port_blacklist']['port_blacklist_list_frame'])
        self.widgets['control']['port_blacklist']['scrollbar'].pack(side=tk.RIGHT, fill=tk.BOTH)
        self.widgets['control']['port_blacklist']['port_blacklist_list'].config(
            yscrollcommand=self.widgets['control']['port_blacklist']['scrollbar'].set)
        self.widgets['control']['port_blacklist']['scrollbar'].config(
            command=self.widgets['control']['port_blacklist']['port_blacklist_list'].yview)

    def add_list(self):
        """
        Creates the list part of the window. Here a preview of each captured packet will be listed.
        The list also features a scrollbar, so any packets which do not fit on the screen will be easily available.
        """
        self.widgets['packet_list'] = {}
        self.widgets['packet_list']['frame'] = tk.Frame(self.window)
        self.widgets['packet_list']['list'] = tk.Listbox(self.widgets['packet_list']['frame'], width=76, height=22)
        self.widgets['packet_list']['header'] = tk.Label(self.widgets['packet_list']['frame'], width=76, height=1, bg=self.colors['ll_main'], anchor='w')
        if os.name == 'posix':
            self.widgets['packet_list']['list'].config(width=84)
            self.widgets['packet_list']['header'].config(width=84)
        self.widgets['packet_list']['header'].grid(row=0, column=0, sticky='ew')
        self.widgets['packet_list']['list'].grid(row=1, column=0, sticky='nsew')
        self.widgets['packet_list']['list'].bind('<Double-Button>', partial(gf.modify_json, self))
        self.add_column_titles()
        self.widgets['packet_list']['scrollbar'] = tk.Scrollbar(self.widgets['packet_list']['frame'])
        self.widgets['packet_list']['scrollbar'].grid(row=1, column=1, sticky='nse')
        self.widgets['packet_list']['list'].config(yscrollcommand=self.widgets['packet_list']['scrollbar'].set)
        self.widgets['packet_list']['scrollbar'].config(command=self.widgets['packet_list']['list'].yview)
        self.widgets['packet_list']['frame'].grid(column=0, row=1, padx=10, pady=10)

    def add_preview(self):
        """
        Creates the preview part of the window. Here a detailed preview of the selected packet will be shown.
        The preview features both a horizontal and a vertical scrollbar, for ease of view.
        """
        self.widgets['preview'] = {}
        self.widgets['preview']['frame'] = tk.Frame(self.window, bg=self.colors['ll_main'])
        self.widgets['preview']['json'] = tk.Text(self.widgets['preview']['frame'], bg=self.colors['l_main'], width=47,
                                                  height=29, wrap=tk.NONE)
        if os.name == 'posix':
            self.widgets['preview']['json'].config(height=31)
        self.widgets['preview']['json'].config(state='disabled')

        # Scrollbar Y
        self.widgets['preview']['scrollbary'] = tk.Scrollbar(self.widgets['preview']['frame'])
        self.widgets['preview']['scrollbary'].pack(side=tk.RIGHT, fill=tk.Y)
        self.widgets['preview']['json'].config(yscrollcommand=self.widgets['preview']['scrollbary'].set)
        self.widgets['preview']['scrollbary'].config(command=self.widgets['preview']['json'].yview)

        # Scrollbar X
        self.widgets['preview']['scrollbarx'] = tk.Scrollbar(self.widgets['preview']['frame'], orient='horizontal')
        self.widgets['preview']['scrollbarx'].pack(side=tk.BOTTOM, fill=tk.X)
        self.widgets['preview']['json'].config(xscrollcommand=self.widgets['preview']['scrollbarx'].set)
        self.widgets['preview']['scrollbarx'].config(command=self.widgets['preview']['json'].xview)

        self.widgets['preview']['json'].pack(side=tk.LEFT, fill=tk.BOTH)
        self.widgets['preview']['frame'].grid(column=1, row=0, rowspan=2)

    def update_preview(self, item):
        """
        Updates the preview part of the window with a new packet.
        It will be formatted as a json with indentation of 2 spaces.

        Keyword arguments:
            item    -- The new packet that should be previewed.
        """
        self.widgets['preview']['json'].config(state='normal')
        self.widgets['preview']['json'].delete(1.0, tk.END)
        self.widgets['preview']['json'].insert(1.0, json.dumps(item, indent=2))
        self.widgets['preview']['json'].config(state='disabled')

    def safe_close(self):
        """Safely closes the program, closing both the sniffer and the GUI."""
        self.STOP = True
        self.window.destroy()

    def add_column_titles(self):
        """Sets the titles for the columns"""
        self.widgets['packet_list']['header'].config(text=f'{gf.align_ip("Source IP", 4)} |  {gf.align_port("Source port")}'
                                                          f'       |       '
                                                          f'{gf.align_ip("Dest IP", 4)}  |  {gf.align_port("Dest port")}'
                                                          f'   |  {gf.align_protocol("Guess")}      |   Certainty')
