from typing import Dict, Any

def format_execute_result(result: Dict[str, Any]) -> str:
    """Format execute command result"""
    output = f"Command: {result['command']}\n"
    if result.get('error'):
        output += f"Error: {result['error']}\n"
    if result.get('output'):
        output += f"Output:\n{result['output']}"
    output += f"\nState: {result['state']}"
    return output


def format_launch_result(result: Dict[str, Any]) -> str:
    """Format launch command result"""
    if not result['success']:
        return f"Launch failed: {result['error']}"
    
    output = f"Launch successful\nState: {result['state']}\n"
    
    # Add load information
    if 'load' in result.get('results', {}):
        load_info = result['results']['load']
        if load_info.get('output'):
            output += f"\nLoad output:\n{load_info['output']}"
    
    # Add context if available
    if 'context' in result.get('results', {}):
        output += "\n\nInitial context:"
        for ctx_type, ctx_data in result['results']['context'].items():
            output += f"\n\n[{ctx_type.upper()}]\n{ctx_data}"
    
    return output


def format_step_result(result: Dict[str, Any]) -> str:
    """Format step control result"""
    if not result['success']:
        return f"Step failed: {result['error']}\nState: {result['state']}"
    
    output = f"Command: {result['command']}\n"
    if result.get('output'):
        output += f"Output:\n{result['output']}\n"
    output += f"State: {result['state']}"
    
    # Add context if stopped
    if result.get('context'):
        output += "\n\nContext after step:"
        for ctx_type, ctx_data in result['context'].items():
            output += f"\n\n[{ctx_type.upper()}]\n{ctx_data}"
    
    return output


def format_context_result(result: Dict[str, Any]) -> str:
    """Format context result"""
    if not result['success']:
        return f"Context error: {result['error']}"
    
    if 'context' in result:
        # Full context
        output = "Full debugging context:"
        for ctx_type, ctx_data in result['context'].items():
            output += f"\n\n[{ctx_type.upper()}]\n{ctx_data}"
        return output
    else:
        # Single context type
        return f"[{result['context_type'].upper()}]\n{result['data']}"


def format_breakpoint_result(result: Dict[str, Any]) -> str:
    """Format breakpoint result"""
    if not result['success']:
        return f"Breakpoint error: {result['error']}"
    return result['output']


def format_memory_result(result: Dict[str, Any]) -> str:
    """Format memory read result"""
    if not result['success']:
        return f"Memory read error: {result['error']}"
    
    output = f"Memory at {result['address']} ({result['size']} bytes, {result['format']} format):\n"
    output += result['data']
    return output


def format_session_result(result: Dict[str, Any]) -> str:
    """Format session info result"""
    import json
    return json.dumps(result, indent=2)


def format_file_result(result: Dict[str, Any]) -> str:
    """Format set_file result"""
    output = ""
    if result.get('error'):
        output += f"Error: {result['error']}\n"
    else:
        output += "Binary loaded successfully\n"
    if result.get('output'):
        output += f"Output:\n{result['output']}"
    output += f"\nState: {result['state']}"
    return output

