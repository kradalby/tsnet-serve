{ buildGoModule, lib }:
buildGoModule {
  pname = "tsnet-serve";
  version = "unstable";
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.fileFilter (
      file:
      file.hasExt "go"
      || builtins.elem file.name [
        "go.mod"
        "go.sum"
      ]
    ) ../.;
  };
  vendorHash = "sha256-29u6OFErZXI/oWLJIB4oyvr+hNMQPKREtm2OlnyL+6Y=";
  subPackages = [ "." ];
  env.CGO_ENABLED = 0;
  meta.mainProgram = "tsnet-serve";
}
