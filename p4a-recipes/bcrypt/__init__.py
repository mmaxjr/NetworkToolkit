from pythonforandroid.recipe import CompiledComponentsPythonRecipe, Recipe


class BCryptRecipe(CompiledComponentsPythonRecipe):
    """
    Overrides python-for-android's built-in bcrypt recipe. The upstream
    recipe's setup.py declares `setup_requires=["cffi>=1.1"]`, which makes
    setuptools try to auto-fetch its own private copy of cffi via
    `fetch_build_eggs` at build time. That fetch runs through a pip call
    that always passes Android cross-compile platform/abi flags, which pip
    refuses to honor without `--target` -- so the fetch always fails
    ("Could not find a version that satisfies cffi==...", later
    "No module named pycparser").

    cffi is already built and installed by the `cffi` recipe (a hard
    dependency of this recipe, see `depends` below), so bcrypt's setup.py
    does not actually need to fetch anything -- the patch below simply
    removes the `setup_requires` line so setup.py uses the already-built
    cffi directly instead of trying (and failing) to fetch a redundant one.
    """

    name = 'bcrypt'
    version = '3.1.7'
    url = 'https://github.com/pyca/bcrypt/archive/{version}.tar.gz'
    depends = ['openssl', 'cffi']
    call_hostpython_via_targetpython = False
    patches = ['no-setup-requires.patch']

    def get_recipe_env(self, arch):
        env = super().get_recipe_env(arch)

        openssl_recipe = Recipe.get_recipe('openssl', self.ctx)
        env['CFLAGS'] += openssl_recipe.include_flags(arch)
        env['LDFLAGS'] += openssl_recipe.link_dirs_flags(arch)
        env['LIBS'] = openssl_recipe.link_libs_flags()

        return env


recipe = BCryptRecipe()
