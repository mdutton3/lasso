Snippet Types
=============

{ name, type, value }; assumes Name as name and Value as value in examples.

SNIPPET_NODE

  <Parent>
    <Value/>
  </Parent>


SNIPPET_CONTENT

  <Parent>
    <Name>Value</Name>
  </Parent>


SNIPPET_TEXT_CHILD

  <Parent>
    Value
  </Parent>


SNIPPET_NAME_IDENTIFIER

  (same result as SNIPPET_NODE)


SNIPPET_ATTRIBUTE

  <Parent Name="Value"/>


SNIPPET_NODE_IN_CHILD

  <Parent>
    <Name>
      <Value/>
    </Name>
  </Parent>


SNIPPET_LIST_NODES

  <Parent>
    <Value-1/>
    <Value-2/>
    <Value-n/>
  </Parent>

[note: if there are no other nodes; it is possible to leave snippet name as
 the empty string; nodes will then be constructed looking at their names and
 namespaces  (this is useful for xs:any)]


SNIPPET_LIST_CONTENT

  <Parent>
    <Name>Value-1</Name>
    <Name>Value-2</Name>
    <Name>Value-n</Name>
  </Parent>

SNIPPET_LIST_XMLNODES

  <Parent>
    <Value-1/>
    <Value-2/>
    <Value-3/>
  </Parent>


SNIPPET_EXTENSION

  (for <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>)

SNIPPET_SIGNATURE

  (for XMLDSig)

