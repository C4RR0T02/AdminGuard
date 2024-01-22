[flake8]
ignore =
    D203,
    # Line break before / after binary operator
    W503, W504, W291, W293,
    # Long lines
    E126
    E501
    E251
    E712
    F403
    F405
exclude =
    .git,
    setup.py,
    __pycache__,
    __init__,
    env,
    app/static,
    old_codes,
    
max-complexity = 25
