import pcapng.blocks as blocks
from pcapng.exceptions import PcapngDumpError


class FileWriter(object):
    """
    pcap-ng file writer.
    """

    __slots__ = [
        "stream",
        "interfaces",
        "current_section",
    ]

    def __init__(self, stream, shb):
        """
        Start writing a new pcap-ng section to the given stream. Writes the
        :py:class:`SectionHeader` immediately. Also writes any
        :py:class:`InterfaceDescription` blocks that have been created for
        the section.

        :param stream:
            a file-like object to which to write the data.

        :param shb:
            a :py:class:`pcapng.blocks.SectionHeader` to start the section.
        """
        self.stream = stream
        self.interfaces = set()
        if not isinstance(shb, blocks.SectionHeader):
            raise TypeError("not a SectionHeader")
        self.current_section = shb
        shb._write(self.stream)
        for iface in sorted(shb.interfaces.keys()):
            self.interfaces.add(iface)
            shb.interfaces[iface]._write(stream)

    def write_block(self, blk):
        """
        Write the given block to this stream.

        If the block is a :py:class:`pcapng.blocks.SectionHeader`, then a new
        section will be started in the same output stream, along with any
        :py:class:`InterfaceDescription` blocks that have been created for the section.

        :param blk:
            a :py:class:`pcapng.blocks.Block` to write.
        """
        if not isinstance(blk, blocks.Block):
            raise TypeError("not a pcapng block")

        if type(blk) is blocks.SectionHeader:
            # Starting a new section, so re-initialize
            self.__init__(self.stream, blk)
            return

        if blk.section is not self.current_section:
            raise PcapngDumpError("block not from current section")

        if type(blk) is blocks.InterfaceDescription:
            # Have we already written this interface?
            if blk.interface_id in self.interfaces:
                # We have. Should this be an error?
                raise PcapngDumpError(
                    "duplicate interface_id {}".format(blk.interface_id)
                )
            # No, so add it
            self.interfaces.add(blk.interface_id)
        elif isinstance(blk, blocks.BlockWithInterfaceMixin):
            # Check that we've written the interface for this block
            if blk.interface.interface_id not in self.interfaces:
                raise PcapngDumpError("no matching interface written for block")

        blk._write(self.stream)
