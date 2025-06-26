# Authors:  Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from AIDojoCoordinator.coordinator import AgentServer
from AIDojoCoordinator.game_components import Action, ActionType, ProtocolConfig

# -----------------------
# Fixtures
# -----------------------
@pytest.fixture
def mock_writer():
    writer = MagicMock()
    writer.get_extra_info.return_value = ('127.0.0.1', 12345)
    return writer

@pytest.fixture
def mock_reader_empty():
    reader = AsyncMock()
    reader.read = AsyncMock(return_value=b'')  # Simulates client disconnect
    return reader

@pytest.fixture
def agent_server():
    actions_queue = asyncio.Queue()
    answers_queues = {}
    max_connections = 3
    return AgentServer(actions_queue, answers_queues, max_connections)

@pytest.fixture
def make_writer_with_peer():
    def _make(ip: str, port: int):
        writer = MagicMock()
        writer.get_extra_info.return_value = (ip, port)
        return writer
    return _make

# -----------------------
# Tests
# -----------------------

# Connection Handling Tests

@pytest.mark.asyncio
async def test_rejects_connection_when_max_connections_reached(agent_server, mock_reader_empty, mock_writer):
    """ Test that the server rejects new connections when max_connections is reached. """
    agent_server.current_connections = agent_server.max_connections

    await agent_server.handle_new_agent(mock_reader_empty, mock_writer)

    mock_writer.close.assert_called_once()
    assert ('127.0.0.1', 12345) not in agent_server.answers_queues


@pytest.mark.asyncio
async def test_accepts_connection_under_max_connections(agent_server, mock_reader_empty, mock_writer):
    """ Test that the server accepts a new connection when under max_connections. """
    peername = mock_writer.get_extra_info.return_value

    await agent_server.handle_new_agent(mock_reader_empty, mock_writer)

    assert agent_server.current_connections == 0  # incremented and decremented
    mock_writer.close.assert_called_once()
    assert peername not in agent_server.answers_queues  # queue should be removed on disconnect


@pytest.mark.asyncio
async def test_accepts_multiple_connections_up_to_limit(agent_server, mock_reader_empty, make_writer_with_peer):
    """ Test that the server accepts multiple connections up to max_connections. """
    for i in range(agent_server.max_connections):
        peername = (f'10.0.0.{i}', 1000 + i)
        writer = make_writer_with_peer(*peername)

        await agent_server.handle_new_agent(mock_reader_empty, writer)

        writer.close.assert_called_once()
        assert peername not in agent_server.answers_queues  # queue created and removed

@pytest.mark.asyncio
async def test_prevents_simultaneous_duplicate_peername_connections(agent_server):
    """Test that two peers with the same name cannot be connected at the same time."""
    peername = ('192.168.1.10', 5555)
    writer1 = MagicMock()
    writer1.get_extra_info.return_value = peername
    writer2 = MagicMock()
    writer2.get_extra_info.return_value = peername
    reader1 = AsyncMock()
    reader1.read = AsyncMock(return_value=b'')  # Simulate disconnect
    reader2 = AsyncMock()
    reader2.read = AsyncMock(return_value=b'')  # Simulate disconnect

    # Patch answers_queues to simulate a long-lived connection for writer1
    with patch.object(agent_server, "answers_queues", {peername: asyncio.Queue()}):
        # Try to connect writer2 while writer1 is "connected"
        await agent_server.handle_new_agent(reader2, writer2)
        writer2.close.assert_called_once()
        # The answers_queues should still only have one entry for the peername
        assert list(agent_server.answers_queues.keys()).count(peername) == 1

    # Now connect writer1 (should be accepted and then removed on disconnect)
    await agent_server.handle_new_agent(reader1, writer1)
    writer1.close.assert_called_once()
    assert peername not in agent_server.answers_queues


# -----------------------
# Queue Management
# -----------------------

@pytest.fixture
def mock_reader_with_data():
    reader = AsyncMock()
    # Simulate one incoming message, then disconnect
    reader.read = AsyncMock(side_effect=[
        b'{"some":"message"}',  # first message
        b''  # disconnect
    ])
    return reader

@pytest.fixture
def response_queue():
    queue = asyncio.Queue()
    queue.put_nowait('{"response":"ok"}')
    return queue

@pytest.mark.asyncio
async def test_creates_and_removes_queue(agent_server, mock_writer):
    """ Test that a queue is created for a new agent and removed on disconnect. """
    peername = mock_writer.get_extra_info.return_value

    # Simulate incoming data, then disconnect
    reader = AsyncMock()
    # We'll insert a response after the server creates the queue
    async def read_side_effect(*_):
        # Wait for the queue to be created
        while peername not in agent_server.answers_queues:
            await asyncio.sleep(0.01)

        # Put dummy response so the handler can proceed
        await agent_server.answers_queues[peername].put("dummy-response")
        return b'{"some":"data"}'  # Fake message from agent

    reader.read = AsyncMock(side_effect=[read_side_effect(), b''])

    await agent_server.handle_new_agent(reader, mock_writer)

    # Assert the queue was created and later removed on disconnect
    assert peername not in agent_server.answers_queues
    mock_writer.close.assert_called_once()

@pytest.mark.asyncio
async def test_does_not_create_queue_if_one_exists(agent_server, mock_reader_empty, mock_writer):
    """ Test that if a queue already exists for a peer, it does not create a new one. """
    peername = mock_writer.get_extra_info.return_value
    preexisting_queue = asyncio.Queue()
    agent_server.answers_queues[peername] = preexisting_queue  # simulate existing queue

    await agent_server.handle_new_agent(mock_reader_empty, mock_writer)

    # Connection should be closed immediately
    mock_writer.close.assert_called_once()

    # Queue should still be there, untouched
    assert agent_server.answers_queues[peername] is preexisting_queue

@pytest.mark.asyncio
async def test_handles_missing_queue_on_cleanup_gracefully(agent_server, mock_reader_empty, mock_writer):
    """ Test that the server handles missing queue on cleanup gracefully. """
    peername = mock_writer.get_extra_info.return_value
    # Do not insert a queue — simulate missing queue at cleanup

    await agent_server.handle_new_agent(mock_reader_empty, mock_writer)

    # Should not raise an exception and should still close connection
    mock_writer.close.assert_called_once()
    assert peername not in agent_server.answers_queues

# -----------------------
# Data Exchange
# -----------------------

@pytest.mark.asyncio
async def test_agent_disconnect_inserts_quit_message(agent_server, mock_writer):
    """Test that when an agent disconnects, the server inserts a QuitGame message into the actions queue."""
    peername = mock_writer.get_extra_info.return_value

    # Prepare a reader that returns b'' (disconnect) immediately
    reader = AsyncMock()
    reader.read = AsyncMock(return_value=b'')

    # Patch the actions_queue to monitor put calls
    agent_server.actions_queue = AsyncMock()
    agent_server.answers_queues = {}

    await agent_server.handle_new_agent(reader, mock_writer)

    # Check that a QuitGame action was put into the actions_queue
    assert agent_server.actions_queue.put.await_count == 1
    args = agent_server.actions_queue.put.await_args[0][0]
    addr, quit_message = args
    assert addr == peername
    action = Action.from_json(quit_message)
    assert action.type == ActionType.QuitGame
    
@pytest.mark.asyncio
async def test_agent_message_is_placed_in_queue(agent_server, mock_writer):
    """Test that when the server receives a message from the agent, it is placed in the actions queue."""
    peername = mock_writer.get_extra_info.return_value

    # Prepare a reader that returns a valid Action JSON, then disconnects
    action = Action(ActionType.FindServices, parameters={"source_host": "10.0.0.1", "target_host": "10.0.0.2"}).to_json()
    reader = AsyncMock()
    reader.read = AsyncMock(side_effect=[action.encode(), b''])

    # Patch the actions_queue to monitor put calls
    agent_server.actions_queue = AsyncMock()
    agent_server.answers_queues = {}

    # Start the handler as a background task
    handler_task = asyncio.create_task(agent_server.handle_new_agent(reader, mock_writer))

    # Wait for the queue to be created by the handler
    for _ in range(100):
        await asyncio.sleep(0.01)
        if peername in agent_server.answers_queues:
            break
    else:
        handler_task.cancel()
        pytest.fail("answers_queues was not created in time")

    # Put a dummy response so the handler can proceed
    await agent_server.answers_queues[peername].put("dummy-response")

    await handler_task

    # Check that the action was put into the actions_queue
    assert agent_server.actions_queue.put.await_count >= 1
    # The first put should be the agent's message
    addr, msg = agent_server.actions_queue.put.await_args_list[0][0][0]
    assert addr == peername
    # The message should be the same as sent
    assert msg == action

@pytest.mark.asyncio
async def test_answer_queue_response_is_sent_to_agent(agent_server, mock_writer):
    """Test that if something is in the answer queue, it is sent to the agent."""
    peername = mock_writer.get_extra_info.return_value

    # Prepare a reader that returns a valid Action JSON, then disconnects
    action = Action(ActionType.FindServices, parameters={"source_host": "10.0.0.1", "target_host": "10.0.0.2"}).to_json()
    reader = AsyncMock()
    reader.read = AsyncMock(side_effect=[action.encode(), b''])

    # Patch the actions_queue to monitor put calls
    agent_server.actions_queue = AsyncMock()
    agent_server.answers_queues = {}

    # Patch writer.write and writer.drain to monitor calls
    mock_writer.write = MagicMock()
    mock_writer.drain = AsyncMock()

    # Start the handler as a background task
    handler_task = asyncio.create_task(agent_server.handle_new_agent(reader, mock_writer))

    # Wait for the queue to be created by the handler
    for _ in range(100):
        await asyncio.sleep(0.01)
        if peername in agent_server.answers_queues:
            break
    else:
        handler_task.cancel()
        pytest.fail("answers_queues was not created in time")

    # Put a response in the answer queue
    response = '{"response": "ok"}'
    await agent_server.answers_queues[peername].put(response)
    assert agent_server.answers_queues[peername].qsize() == 1
    # Wait for the handler to process the response
    await handler_task
    # Check that the response was sent to the agent
    expected_bytes = response.encode() + getattr(ProtocolConfig, "END_OF_MESSAGE", b'EOF')
    mock_writer.write.assert_any_call(expected_bytes)
    mock_writer.drain.assert_awaited()