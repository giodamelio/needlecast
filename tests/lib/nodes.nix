{
  pkgs,
  needlecast,
  kernelPackages,
}: {
  # Shared machine definition so sysctls and tooling are declared once and every test observes the
  # same environment. The kernel is a parameter because the programs have to work on the kernel you
  # actually run, not only on the newest one.
  laptop = {...}: {
    boot.kernelPackages = kernelPackages;

    environment.systemPackages = with pkgs; [
      needlecast
      bpftools
      curl
      iproute2
      python3
      socat
      tcpdump
      util-linux
    ];

    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
  };
}
