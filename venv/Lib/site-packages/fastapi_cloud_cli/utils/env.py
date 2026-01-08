def validate_environment_variable_name(name: str) -> bool:
    if name.isidentifier():
        return True

    return False
