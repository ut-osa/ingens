import gdb

from linux import utils


def osa_page_to_pfn(page):
    gdb.write("page_to_pfn")
    return

class osaPageUtil(gdb.Command):
    """ useful tools for page """

    def __init__(self):
        super(osaPageUtil, self).__init__("lx-page_to_pfn", gdb.COMMAND_DATA,
                gdb.COMPLETE_EXPRESSION)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)

        if len(argv) != 1:
            raise gdb.GdbError("need arguement of struct page")

        osa_page_to_pfn(argv[0])

osaPageUtil()
