#!/usr/bin/env python
# coding: shift-jis
from lxml import etree as ET

class XmlWapper:
    """
    This is sample code.
    This class create new xml file
    This class can't do anything else..
    """

    def __init__(self):
        """Initialize
        """
        self.root = ET.Element("Packets")
        self.tree = ET.ElementTree(self.root)
        
    def add_node(self, node):
        return ET.SubElement(self.root, node)

    def add_leaf(self, node, leaf):
        return ET.SubElement(node, leaf)

    def add_attribute(self, node, attribute, attribute_value):
        node.set(attribute, str(attribute_value))

    def save(self, name):
        """Save xml file.

        Parameters
        ----------
        name : str
            File name
        """
        self.tree.write(name, pretty_print=True, xml_declaration=True, encoding='UTF-8')
        return
