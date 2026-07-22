from pythonforandroid.recipe import CompiledComponentsPythonRecipe
import os


class PyNaCLRecipe(CompiledComponentsPythonRecipe):
    """
    Overrides python-for-android's built-in pynacl recipe. Same issue as
    the local `bcrypt` recipe override: setup.py appends `cffi>=1.4.1` to
    `setup_requirements`, which makes setuptools try to auto-fetch its own
    copy of cffi at build time via a pip call that always fails under
    Android cross-compilation (platform/abi flags without --target). cffi
    is already built by the `cffi` recipe (a dependency below), so this
    patch just removes that redundant, always-failing fetch attempt.
    """

    name = 'pynacl'
    version = '1.3.0'
    url = 'https://pypi.python.org/packages/source/P/PyNaCl/PyNaCl-{version}.tar.gz'

    depends = ['hostpython3', 'six', 'setuptools', 'cffi', 'libsodium']
    call_hostpython_via_targetpython = False
    patches = ['no-setup-requires.patch']

    def get_recipe_env(self, arch):
        env = super().get_recipe_env(arch)
        env['SODIUM_INSTALL'] = 'system'

        libsodium_build_dir = self.get_recipe(
            'libsodium', self.ctx).get_build_dir(arch.arch)
        env['CFLAGS'] += ' -I{}'.format(os.path.join(libsodium_build_dir,
                                                     'src/libsodium/include'))
        env['LDFLAGS'] += ' -L{}'.format(
            self.ctx.get_libs_dir(arch.arch) +
            '-L{}'.format(self.ctx.libs_dir)) + ' -L{}'.format(
            libsodium_build_dir)

        return env


recipe = PyNaCLRecipe()
