.. include:: references.rst
.. _backendapi:

***********
Backend API
***********

As there can be various use-case scenarios for Jetconf, bindings to a user application
are not part of Jetconf server itself, but instead they are implemented in a separate package,
so called *"Jetconf backend"*.

The basic idea of Jetconf's backend architecture is that every node of the YANG schema
(i.e. container, list, leaf-list) can have a custom handler object assigned to it.
When a specific event affecting this node occurs , like configuration data being rewritten
or RESCONF operation is called, an appropriate member function of this node handler is invoked.

As there are some major differences between YANG configuration data, state data and RPCs,
the architecture of corresponding node handlers in Jetconf also has to follow these differences.

Backend package architecture
============================

Every backend package for Jetconf server has to provide implementation of following modules.

- ``usr_conf_data_handlers`` (Handlers for configuration data)
- ``usr_state_data_handlers`` (Handlers for state data)
- ``usr_op_handlers`` (Handlers for RESTCONF operations - RPCs)
- ``us_action_handlers`` (Handlers for RESTCONF actions - operation on node)
- ``usr_datastore`` (Datastore initialization and save/load functions can be customized here)
- ``usr_init`` (Jetconf initialization)

In addition to this, backend package can also contain any other resources if necessary.
When you consider writing a custom backend, looking at the very basic demo package
jukebox-jetconf_ is a good way to start.

Handler inheritance
===================
Because some data models can be quite large, it would be difficult to manually assign
handler objects to all schema nodes. Because of this, for configuration and state data handlers,
Jetconf offers a feature called **Handler inheritance**.

If a node without its own handler is edited, Jetconf finds a nearest
parent node which has the handler assigned and then it calls its ``replace`` or ``replace_item``
method. It's up to backend developer's decision where to place handler objects, a more fine-grained
placement will usually mean better performance (less data rewriting), at the cost of more work.


usr_init
========

Useful for code that has to be executed on the startup or on the end of Jetconf backend.

.. code-block:: python

    def jc_startup():

        # execute code on startup

    def jc_end():

        # execute code on end

usr_datastore
=============

Basic ``usr_datastore`` module without any customization.

.. code-block:: python

    from jetconf.data import JsonDatastore

    class UserDatastore(JsonDatastore):
        pass


Customizing ``load()`` and ``save()`` functions

.. code-block:: python

    from jetconf.data import JsonDatastore


    class UserDatastore(JsonDatastore):

        def load(self):

            # load method can be customized here

        def save(self):

            # save method can be customized here


usr_conf_data_handlers
======================

The main purpose of configuration data handlers is to project all changes performed on a
particular data node, like creation, modification or deletion, to the user application.

A configuration node handler is implemented by creating a custom class which inherits
from either ``ConfDataObjectHandler`` or ``ConfDataListHandler`` base class depending on
the type of YANG node. The former must be used when implementing a handler for ``Container``
or ``Leaf`` data nodes, while the latter is used for list-like types, specifically ``List``
and ``Leaf-List``.

ConfDataObjectHandler:
^^^^^^^^^^^^^^^^^^^^^^

**Attributes**:

.. code-block:: python

    self.ds             # type: jetconf.data.BaseDatastore
                        # Can be used for accessing the datastore content from handler functions

    self.schema_path    # type: str
                        # Contains the YANG schema path to which this handler object is registered (as string)

    self.schema_node    # type: yangson.schemanode.SchemaNode
                        # Contains the YANG schema path to which this handler object is registered (parsed)

**Arguments**:

.. code-block:: python

    ii:         # type: yangson.instance.InstanceRoute
                # Contains parsed instance identifier of the data node. Useful for determining list keys if this data node is a child of some list node.
    ch:         # type: jetconf.data.DataChange
                # Can be used for accessing additional edit information, like HTTP input data if needed

Handlers derived from this base class has to implement the following interface:

.. code-block:: python

    from jetconf.handler_base import ConfDataObjectHandler
    from yangson.instance import InstanceRoute
    from jetconf.data import BaseDatastore, DataChange


    class MyConfDataHandler(ConfDataObjectHandler):
        def create(self, ii: InstanceRoute, ch: DataChange):

            # Called when a new node is created

        def replace(self, ii: InstanceRoute, ch: DataChange):

            # Called when the node is being rewritten by new data

        def delete(self, ii: InstanceRoute, ch: DataChange):

            # Called when the node is deleted

ConfDataListHandler:
^^^^^^^^^^^^^^^^^^^^

**Attributes**:

.. code-block:: python

    self.ds             # type: jetconf.data.BaseDatastore
                        # Can be used for accessing the datastore content from handler functions

    self.schema_path    # type: str
                        # Contains the YANG schema path to which this handler object is registered (as string)

    self.schema_node    # type: yangson.schemanode.SchemaNode
                        # Contains the YANG schema path to which this handler object is registered (parsed)

**Arguments**:

.. code-block:: python

    ii:     # type: yangson.instance.InstanceRoute
            # Contains parsed instance identifier of the data node. Useful for determining list keys if this data node is a child of some list node.

    ch:     # type: jetconf.data.DataChange
            # Can be used for accessing additional edit information, like HTTP input data if needed

Handlers derived from this base class has to implement the following interface:

.. code-block:: python

    from jetconf.handler_base import ConfDataListHandler
    from yangson.instance import InstanceRoute
    from jetconf.data import BaseDatastore, DataChange


    class MyConfDataHandler(ConfDataListHandler):
        def create_item(self, ii: InstanceRoute, ch: DataChange):

            # Called when a new item is added to the list or leaf-list

        def replace_item(self, ii: InstanceRoute, ch: DataChange):

            # Called when specific list item is being rewritten

        def delete_item(self, ii: InstanceRoute, ch: DataChange):

            # Called when an item is being deleted from the list

Handler registration
^^^^^^^^^^^^^^^^^^^^

Assignation of handler objects to the specific data nodes is done via registering them in
``jetconf.handler_list.CONF_DATA_HANDLES`` handler list. Every ``usr_conf_data_handlers``
backend module must implement the global function ``register_conf_handlers``,
where the instantiation and registration of handler objects is done. This function is
called on Jetconf startup after datastore initialization and has the following signature.

.. code-block:: python

    def register_conf_handlers(ds: BaseDatastore):

        ds.handlers.conf.register(MyConfHandler(ds, "/ns:schema-path/to-desired-node"))


usr_state_data_handlers
=======================

YANG state data, in contrast to the configuration data, represents more of a current
state of the backend application. This means that they are not actually stored in
Jetconf's datastore, but instead they has to be generated on the go. Generation of
state data is the purpose of state data handlers.

A state data handler has to acquire actual state data from backend application and generate data
content of the node where it's assigned. The output data are formatted in Python's representation
of *JSON* (using lists, dicts etc.) and their structure must be compliant with the standardized
JSON encoding of YANG data (RFC7951_).

A state node handler is implemented by creating a custom class which inherits from either
``StateDataContainerHandler`` or ``StateDataListHandler``, depending on the YANG node type.
This is similar to he configuration data handlers.

StateDataContainerHandler
^^^^^^^^^^^^^^^^^^^^^^^^^
**Attributes**:

.. code-block:: python

    self.ds             # type: jetconf.data.BaseDatastore
                        # Can be used for accessing the datastore content from handler functions

    self.data_model     # type: yangson.datamodel.DataModel
                        # Reference to the current data model object

    self.sch_pth        # type: str
                        # YANG schema path to which this handler object is registered (as string)

    self.schema_node    # type: yangson.schemanode.DataNode
                        # Reference to the Yangson schema node object



.. code-block:: python

    from yangson.instance import InstanceRoute
    from jetconf.handler_base import StateDataContainerHandler
    from jetconf.data import BaseDatastore

    class MyStateDataHandler(StateDataContainerHandler):
        def generate_node(self, node_ii: InstanceRoute, username: str, staging: bool)

            # This method has to generate content of the state data node

            return generated_content


StateDataListHandler
^^^^^^^^^^^^^^^^^^^^

**Attributes**:

.. code-block:: python

    self.ds             # type: jetconf.data.BaseDatastore
                        # Can be used for accessing the datastore content from handler functions

    self.data_model     # type: yangson.datamodel.DataModel
                        # Reference to the current data model object

    self.sch_pth        # type: str
                        # YANG schema path to which this handler object is registered (as string)

    self.schema_node    # type: yangson.schemanode.DataNode
                        # Reference to the Yangson schema node object

**Methods**:

.. code-block:: python

    from yangson.instance import InstanceRoute
    from jetconf.helpers import JsonNodeT
    from jetconf.handler_base import StateDataListHandler
    from jetconf.data import BaseDatastore

    class MyStateDataHandler(StateDataListHandler):
        def generate_list(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:

            # This method has to generate entire list

            return generated_content

        def generate_list(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:

            # Generates only one specific item of the list. The list key(s) of the item which needs to be generated can be resolved by processing the instance identifier passed in 'node_ii' argument.

            return generated_content

Handler registration
^^^^^^^^^^^^^^^^^^^^

Assignation of state data handler objects to the specific data nodes is done via registering
them in ``jetconf.handler_list.STATE_DATA_HANDLERS`` handler list. This is similar to the configuration data.
Every ``usr_state_data_handlers`` backend module must implement the global function ``register_state_handlers``,
where the instantiation and registration of handler objects is done. This function is called on Jetconf
startup after datastore initialization and has the following signature:

.. code-block:: python

    def register_state_handlers(ds: BaseDatastore):

        ds.handlers.state.register(MyStateDataHandler(ds, "/ns:schema-path/to/state/node"))


usr_op_handlers
===============
Handlers for RESTCONF operations.

**Arguments**:

.. code-block:: python

     input_args:        # type: JSON
                        # Operation input arguments with structure defined by YANG model

     username:          # type: jetconf.data.BaseDatastore
                        # Name of the user who invoked the operation

An operation handlers are implemented by adding a custom method to
the class ``OpHandlersContainer``. Finally, this class is instantiated and its methods are assigned
to specific operation names.

.. code-block:: python

    from yangson.instance import InstanceRoute
    from jetconf.helpers import JsonNodeT
    from jetconf.data import BaseDatastore

    class OpHandlersContainer:
        def __init__(self, ds: BaseDatastore):
            self.ds = ds

        def my_op_handler(self, input_args: JsonNodeT, username: str) -> JsonNodeT:

            # RPC operation Body

            # Operation output data as defined by YANG data model
            # output is not mandatory
            return output_data

Handler registration
^^^^^^^^^^^^^^^^^^^^

Every ``usr_op_handlers`` backend module must implement the global function ``register_op_handlers``,
where the class ``OpHandlersContainer`` is instantiated and its methods are tied to individual
operations. This function with following signature is called on Jetconf startup after datastore
initialization.

.. code-block:: python

    def register_op_handlers(ds: BaseDatastore):

        op_handlers_obj = OpHandlersContainer(ds)
        ds.handlers.op.register(op_handlers_obj.my_op_handler, "ns:operation")



us_action_handlers
==================
Handlers for RESTCONF actions.

**Arguments**:

.. code-block:: python

     ii:     # type: yangson.instance.InstanceRoute
            # Contains parsed instance identifier of the data node. Useful for determining list keys if this data node is a child of some list node.

     input_args:        # type: JSON
                        # Operation input arguments with structure defined by YANG model

     username:          # type: jetconf.data.BaseDatastore
                        # Name of the user who invoked the operation


An action handlers are implemented by adding a custom method to
the class ``ActionHandlersContainer``. Finally, this class is instantiated and its methods are assigned
to specific action names and node path.

.. code-block:: python

    from yangson.instance import InstanceRoute
    from jetconf.helpers import JsonNodeT
    from jetconf.data import BaseDatastore

    class ActionHandlersContainer:
        def __init__(self, ds: BaseDatastore):
            self.ds = ds

        def my_action_handler(self, ii: InstanceRoute, input_args: JsonNodeT, username: str) -> JsonNodeT:

            # Action Body

            # Action output data as defined by YANG data model
            # output is not mandatory
            return output_data


Handler registration
^^^^^^^^^^^^^^^^^^^^
Every ``usr_action_handlers`` backend module must implement the global function ``register_action_handlers``,
where the class ``ActionHandlersContainer`` is instantiated and its methods are tied to individual
actions. This function with following signature is called on Jetconf startup after datastore
initialization.

.. code-block:: python

    def register_action_handlers(ds: BaseDatastore):
        act_handlers_obj = ActionHandlersContainer(ds)
        ds.handlers.action.register(act_handlers_obj.my_action_handler, "/ns:schema-path/to/action/node")

