from clang.cindex import Index, Config
import sys

Config.set_library_file(r"C:\Users\LAU1HYD\.conda\envs\hsmtool\Library\bin\libclang-13.dll")

index = Index.create()
tu = index.parse(
    sys.argv[1],
    args=["-Isample", "-x", "c"]
)

def dump(node, indent=0):
    print("  " * indent, node.kind, node.spelling, node.displayname)
    for c in node.get_children():
        dump(c, indent+1)

dump(tu.cursor)
