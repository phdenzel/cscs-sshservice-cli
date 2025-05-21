{
  pkgs ? import <nixpkgs> {},
  src ? ./.,
  # subdir ? "",
}:
let 
  pythonPackage = pkgs.python312Packages.buildPythonApplication {
    pname = "cscs-keygen";
    version = "0.1.dev0";
    format = "pyproject";
    build-system = with pkgs.python312Packages; [hatchling];
    propagatedBuildInputs = with pkgs.python312Packages; [
      requests
      passpy
      pyotp
    ];
    src = src;
    doCheck = false;
    meta = {
      description = "Utility script to fetch CSCS' CA-signed SSH keys from API";
      meta.description.license = pkgs.lib.licenses.gpl3;
    };
  };
  passpy = pkgs.python312Packages.buildPythonPackage {
    pname = "passpy";
    version = "1.0.2";
    propagatedBuildInputs = with pkgs.python312Packages; [
      gitpython
      python-gnupg
      pyperclip
      click
    ];
    src = pkgs.fetchFromGitHub {
      owner = "bfrascher";
      repo = "passpy";
      rev = "c6171e4494cac60443a0605d340acfd709d40b12";
      sha256 = "sha256-QQkCA5cQY5srlFtuSww6LqAJYLd90B5k9K4+Bo+JQBI=";
    };
    doCheck = false;
  };
in [
  pythonPackage
]
