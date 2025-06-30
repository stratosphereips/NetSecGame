# Authors: Ondřej Lukas - ondrej.lukas@aic.fel.cvut.cz
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from contextlib import suppress
from AIDojoCoordinator.coordinator import AgentServer
from AIDojoCoordinator.game_components import Action, ActionType, ProtocolConfig

# -----------------------
# Fixtures
# -----------------------

@pytest.fixture
def mock_writer():
    writer = AsyncMock()
    writer.get_extra_info = MagicMock(return_value=('127.0.0.1', 12345))  # ✅ Sync method
    writer.write = MagicMock()                                           # ✅ Sync method
    writer.drain = AsyncMock()                                           # ✅ Async method
    writer.close = AsyncMock()                                           # ✅ Async method
    return writer

@pytest.fixture
def mock_reader_empty():
    reader = AsyncMock()
    reader.read = AsyncMock(return_value=b'')  # Simulates client disconnect
    return reader

@pytest.fixture
def mock_reader_with_data():
    reader = AsyncMock()
    reader.read = AsyncMock(side_effect=[
        b'{"some":"message"}',  # first message
        b''                     # then disconnect
    ])
    return reader

@pytest.fixture
def response_queue():
    q = asyncio.Queue()
    q.put_nowait('{"response":"ok"}')
    return q

@pytest.fixture
def agent_server():
    actions_queue = asyncio.Queue()
    answers_queues = {}
    max_connections = 3
    return AgentServer(actions_queue, answers_queues, max_connections)

@pytest.fixture
def make_writer_with_peer():
    def _make(ip: str, port: int):
        writer = AsyncMock()
        writer.get_extra_info = MagicMock(return_value=(ip, port))  # get_extra_info is sync
        writer.write = MagicMock()                                   # write is sync
        writer.drain = AsyncMock()                                   # drain is async
        writer.close = AsyncMock()                                   # close is async
        return writer
    return _make

# -----------------------
# Connection Handling Tests
# -----------------------

@pytest.mark.asyncio
async def test_rejects_connection_when_max_connections_reached(agent_server, mock_reader_empty, mock_writer):
    agent_server.current_connections = agent_server.max_connections
    await agent_server.handle_new_agent(mock_reader_empty, mock_writer)
    assert ('127.0.0.1', 12345) not in agent_server.answers_queues

@pytest.mark.asyncio
async def test_accepts_connection_under_max_connections(agent_server, mock_reader_empty, mock_writer):
    peername = ('127.0.0.1', 12345)
    mock_writer.get_extra_info = MagicMock(return_value=peername)

    await agent_server.handle_new_agent(mock_reader_empty, mock_writer)

    # incremented and decremented → back to zero
    assert agent_server.current_connections == 0
    mock_writer.close.assert_called_once()
    assert peername not in agent_server.answers_queues

@pytest.mark.asyncio
async def test_accepts_multiple_connections_up_to_limit(agent_server, mock_reader_empty, make_writer_with_peer):
    for i in range(agent_server.max_connections):
        peername = (f'10.0.0.{i}', 1000 + i)
        writer = make_writer_with_peer(*peername)
        await agent_server.handle_new_agent(mock_reader_empty, writer)
        writer.close.assert_called_once()
        assert peername not in agent_server.answers_queues

@pytest.mark.asyncio
async def test_prevents_simultaneous_duplicate_peername_connections(agent_server, make_writer_with_peer):
    peername = ('192.168.1.10', 5555)
    writer1 = make_writer_with_peer(*peername)
    writer2 = make_writer_with_peer(*peername)

    writer1.get_extra_info = MagicMock(return_value=peername)
    writer2.get_extra_info = MagicMock(return_value=peername)

    # First reader hangs to simulate a long-lived connection
    async def never_read(_=None):
        await asyncio.Event().wait()

    reader1 = AsyncMock()
    reader2 = AsyncMock()
    reader1.read = AsyncMock(side_effect=never_read)
    reader2.read = AsyncMock(return_value=b'')

    agent_server.actions_queue = AsyncMock()

    # Start first connection
    task1 = asyncio.create_task(agent_server.handle_new_agent(reader1, writer1))

    # Wait until queue for writer1 is created
    for _ in range(100):
        await asyncio.sleep(0.01)
        if peername in agent_server.answers_queues:
            break
    else:
        task1.cancel()
        with suppress(asyncio.CancelledError):
            await task1
        pytest.fail("answers_queues was not created in time")

    # Assert queue exists before it's potentially removed
    assert list(agent_server.answers_queues.keys()).count(peername) == 1

    # Start second connection with the same peername
    await agent_server.handle_new_agent(reader2, writer2)

    # Assert it was rejected (writer2 should be closed)
    writer2.close.assert_called_once()

    # Clean up task1
    task1.cancel()
    with suppress(asyncio.CancelledError):
        await task1



# -----------------------
# Queue Management Tests
# -----------------------

@pytest.mark.asyncio
async def test_does_not_create_queue_if_one_exists(agent_server, mock_reader_empty, mock_writer):
    peername = ('127.0.0.1', 12345)
    mock_writer.get_extra_info = MagicMock(return_value=peername)
    preexisting = asyncio.Queue()
    agent_server.answers_queues = {peername: preexisting}

    await agent_server.handle_new_agent(mock_reader_empty, mock_writer)
    mock_writer.close.assert_called_once()
    assert agent_server.answers_queues[peername] is preexisting

@pytest.mark.asyncio
async def test_handles_missing_queue_on_cleanup_gracefully(agent_server, mock_reader_empty, mock_writer):
    peername = ('127.0.0.1', 12345)
    mock_writer.get_extra_info = MagicMock(return_value=peername)
    agent_server.answers_queues = {}  # missing

    await agent_server.handle_new_agent(mock_reader_empty, mock_writer)
    mock_writer.close.assert_called_once()
    assert peername not in agent_server.answers_queues

# -----------------------
# Data Exchange Tests
# -----------------------

@pytest.mark.asyncio
async def test_quit_message_is_sent_on_disconnect(agent_server, mock_writer):
    peername = ('127.0.0.1', 12345)
    mock_writer.get_extra_info = MagicMock(return_value=peername)

    reader = AsyncMock(); reader.read = AsyncMock(return_value=b'')
    agent_server.actions_queue = AsyncMock()
    agent_server.answers_queues = {}

    await agent_server.handle_new_agent(reader, mock_writer)

    # Queue cleaned
    assert peername not in agent_server.answers_queues
    agent_server.actions_queue.put.assert_awaited_once()

    (addr, msg) = agent_server.actions_queue.put.call_args[0][0]
    assert addr == peername
    expected = Action(ActionType.QuitGame, parameters={}).to_json()
    assert msg == expected

@pytest.mark.asyncio
async def test_agent_message_is_placed_in_queue(agent_server, mock_writer):
    peername = ('127.0.0.1', 12345)
    mock_writer.get_extra_info = MagicMock(return_value=peername)

    action = Action(
        ActionType.FindServices,
        parameters={"source_host": "10.0.0.1", "target_host": "10.0.0.2"}
    ).to_json()

    reader = AsyncMock()
    reader.read = AsyncMock(side_effect=[action.encode(), b''])

    agent_server.actions_queue = AsyncMock()
    agent_server.answers_queues = {}

    task = asyncio.create_task(agent_server.handle_new_agent(reader, mock_writer))

    # wait for queue creation
    for _ in range(100):
        await asyncio.sleep(0.01)
        if peername in agent_server.answers_queues:
            break
    else:
        task.cancel()
        pytest.fail("answers_queues was not created in time")

    await agent_server.answers_queues[peername].put("dummy-response")
    await task

    assert agent_server.actions_queue.put.await_count >= 1
    (addr, msg) = agent_server.actions_queue.put.call_args_list[0][0][0]
    assert addr == peername
    assert msg == action

@pytest.mark.asyncio
async def test_answer_queue_response_is_sent_to_agent(agent_server, mock_writer):
    peername = ('127.0.0.1', 12345)
    mock_writer.get_extra_info = MagicMock(return_value=peername)

    action = Action(
        ActionType.FindServices,
        parameters={"source_host": "10.0.0.1", "target_host": "10.0.0.2"}
    ).to_json()

    reader = AsyncMock()
    reader.read = AsyncMock(side_effect=[action.encode(), b''])

    agent_server.actions_queue = AsyncMock()
    agent_server.answers_queues = {}
    mock_writer.write = MagicMock()
    mock_writer.drain = AsyncMock()

    task = asyncio.create_task(agent_server.handle_new_agent(reader, mock_writer))

    for _ in range(100):
        await asyncio.sleep(0.01)
        if peername in agent_server.answers_queues:
            break
    else:
        task.cancel()
        pytest.fail("answers_queues was not created in time")

    response = '{"response":"ok"}'
    await agent_server.answers_queues[peername].put(response)
    await task

    delimiter = getattr(ProtocolConfig, "END_OF_MESSAGE", b"\n")
    expected = response.encode() + delimiter
    mock_writer.write.assert_any_call(expected)
    mock_writer.drain.assert_called_once()

# -----------------------
# Error Handling Tests
# -----------------------

@pytest.mark.asyncio
async def test_cancelled_error_cleanup(agent_server, mock_writer):
    peername = ('127.0.0.1', 12345)
    mock_writer.get_extra_info = MagicMock(return_value=peername)
    mock_writer.close = AsyncMock()
    mock_writer.wait_closed = AsyncMock()
    reader = AsyncMock()
    reader.read = AsyncMock(side_effect=asyncio.CancelledError())

    agent_server.actions_queue = AsyncMock()
    agent_server.answers_queues = {}

    with pytest.raises(asyncio.CancelledError):
        await agent_server.handle_new_agent(reader, mock_writer)

    assert peername not in agent_server.answers_queues
    mock_writer.close.assert_called_once()            
    mock_writer.wait_closed.assert_awaited_once()    

@pytest.mark.asyncio
async def test_unexpected_exception_cleanup(agent_server, mock_writer):
    peername = ('127.0.0.1', 12345)
    mock_writer.get_extra_info = MagicMock(return_value=peername)

    reader = AsyncMock()
    reader.read = AsyncMock(side_effect=[b'{"some":"data"}', b''])

    agent_server.actions_queue = AsyncMock()
    agent_server.actions_queue.put.side_effect = Exception("Unexpected error")
    agent_server.answers_queues = {}

    with pytest.raises(Exception, match="Unexpected error"):
        await agent_server.handle_new_agent(reader, mock_writer)

    assert peername not in agent_server.answers_queues
    mock_writer.close.assert_called_once()