from clang import cindex
import os

print("CONDA_PREFIX =", os.environ.get("CONDA_PREFIX"))

cindex.Config.set_library_file(
    r"C:\Users\LAU1HYD\.conda\envs\hsmtool\Library\bin\libclang-13.dll"
)

idx = cindex.Index.create()

tu = idx.parse(
    "crypto_file/sample.c",
    args=["-Icrypto_file/crytpo", "-Icrypto_file/fake_headers"]
)

print("TU diagnostics:")
for d in tu.diagnostics:
    print("  DIAG:", d)

print("Top-level children:", len(list(tu.cursor.get_children())))

for c in tu.cursor.get_children():
    print("  node:", c.spelling, c.kind)
