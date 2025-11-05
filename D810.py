import os
import idaapi
import ida_hexrays
import ida_kernwin


from d810.conf import D810Configuration
from d810.manager import D810State, D810_LOG_DIR_NAME
from d810.log import configure_loggers, clear_logs


D810_VERSION = "0.1"

class D810Plugin(idaapi.plugin_t):
    # variables required by IDA
    flags = 0  # normal plugin
    wanted_name = "D-810"
    wanted_hotkey = "Ctrl-Shift-D"
    comment = "Interface to the D-810 plugin"
    help = ""
    initialized = False

    def __init__(self):
        super(D810Plugin, self).__init__()
        self.d810_config = None
        self.state = None
        self.initialized = False


    def reload_plugin(self):
        if self.initialized:
            self.term()

        try:
            self.d810_config = D810Configuration()
        except Exception as e:
            print("D-810 configuration error: {0}".format(e))
            return

        try:
            log_dir = self.d810_config.get("log_dir")
            if log_dir is None:
                log_dir = os.path.dirname(os.path.abspath(__file__))
            real_log_dir = os.path.join(log_dir, D810_LOG_DIR_NAME)
        except (KeyError, Exception) as e:
            print("D-810 error getting log_dir: {0}".format(e))
            return

        try:
            erase_logs = self.d810_config.get("erase_logs_on_reload")
            if erase_logs:
                clear_logs(real_log_dir)
        except (KeyError, Exception) as e:
            print("D-810 warning: could not erase logs: {0}".format(e))

        try:
            configure_loggers(real_log_dir)
            self.state = D810State(self.d810_config)
            print("D-810 reloading...")
            self.state.start_plugin()
            self.initialized = True
        except Exception as e:
            print("D-810 initialization error: {0}".format(e))
            self.initialized = False


    # IDA API methods: init, run, term
    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            print("D-810 need Hex-Rays decompiler. Skipping")
            return idaapi.PLUGIN_SKIP

        try:
            kv = ida_kernwin.get_kernel_version().split(".")
            major = int(kv[0])
            minor = int(kv[1]) if len(kv) > 1 else 0
            if major < 7 or (major == 7 and minor < 5):
                print("D-810 needs IDA version >= 7.5. Current version: {0}.{1}. Skipping".format(major, minor))
                return idaapi.PLUGIN_SKIP
        except (ValueError, IndexError) as e:
            print("D-810 error checking IDA version: {0}".format(e))
            return idaapi.PLUGIN_SKIP
        print("D-810 initialized (version {0})".format(D810_VERSION))
        return idaapi.PLUGIN_OK


    def run(self, args):
        self.reload_plugin()


    def term(self):
        print("Terminating D-810...")
        if self.state is not None:
            self.state.stop_plugin()

        self.initialized = False


def PLUGIN_ENTRY():
    return D810Plugin()
