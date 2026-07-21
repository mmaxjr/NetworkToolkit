from pythonforandroid.recipe import PythonRecipe


class ParamikoRecipe(PythonRecipe):
    """
    Overrides python-for-android's generic pip-based build of paramiko.

    paramiko unconditionally imports `bcrypt` and `nacl` (PyNaCl) at module
    load time, but both are only actually used for two things we never do in
    this app: loading Ed25519 private keys, and decrypting OpenSSH-format
    private keys encrypted with a bcrypt KDF. We only ever authenticate with
    a username/password, so neither code path is reachable.

    bcrypt and pynacl both have their own long-standing python-for-android
    build bug (their legacy `setup_requires`/`cffi_modules` build hooks don't
    work under Android cross-compilation -- see the local `bcrypt` and
    `pynacl` recipe overrides in this same directory for the full story).
    Rather than fight that a third time, the patch below makes both imports
    optional in paramiko itself, so we can drop bcrypt/pynacl from the app's
    requirements entirely.
    """

    name = 'paramiko'
    version = '2.11.0'
    url = 'https://pypi.python.org/packages/source/p/paramiko/paramiko-{version}.tar.gz'
    depends = ['python3', 'six', 'cryptography']
    call_hostpython_via_targetpython = False
    patches = ['no-bcrypt-nacl.patch']


recipe = ParamikoRecipe()
