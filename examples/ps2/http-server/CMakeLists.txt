cmake_minimum_required(VERSION 3.10)

set(CMAKE_TOOLCHAIN_FILE $ENV{PS2SDK}/ps2dev.cmake)

set(MG_ARCH "UNIX")
project(http-server)

add_custom_command(
    OUTPUT irx/ps2dev9_irx.c
    COMMAND bin2c $ENV{PS2SDK}/iop/irx/ps2dev9.irx irx/ps2dev9_irx.c ps2dev9_irx
    DEPENDS $ENV{PS2SDK}/iop/irx/ps2dev9.irx
)

add_custom_command(
    OUTPUT irx/netman_irx.c
    COMMAND bin2c $ENV{PS2SDK}/iop/irx/netman.irx irx/netman_irx.c netman_irx
    DEPENDS $ENV{PS2SDK}/iop/irx/netman.irx
)

add_custom_command(
    OUTPUT irx/ps2ip_irx.c
    COMMAND bin2c $ENV{PS2SDK}/iop/irx/ps2ip.irx irx/ps2ip_irx.c ps2ip_irx
    DEPENDS $ENV{PS2SDK}/iop/irx/ps2ip.irx
)

add_custom_command(
    OUTPUT irx/smap_irx.c
    COMMAND bin2c $ENV{PS2SDK}/iop/irx/smap.irx irx/smap_irx.c smap_irx
    DEPENDS $ENV{PS2SDK}/iop/irx/smap.irx
)

add_custom_command(
    OUTPUT irx/atad_irx.c
    COMMAND bin2c $ENV{PS2SDK}/iop/irx/ps2atad.irx irx/atad_irx.c atad_irx
    DEPENDS $ENV{PS2SDK}/iop/irx/ps2atad.irx
)

add_custom_command(
    OUTPUT irx/iomanx_irx.c
    COMMAND bin2c $ENV{PS2SDK}/iop/irx/iomanX.irx irx/iomanx_irx.c iomanx_irx
    DEPENDS $ENV{PS2SDK}/iop/irx/iomanX.irx
)


add_custom_command(
    OUTPUT irx/hdd_irx.c
    COMMAND bin2c $ENV{PS2SDK}/iop/irx/ps2hdd.irx irx/hdd_irx.c hdd_irx
    DEPENDS $ENV{PS2SDK}/iop/irx/ps2hdd.irx
)

add_custom_command(
    OUTPUT irx/filexio_irx.c
    COMMAND bin2c $ENV{PS2SDK}/iop/irx/fileXio.irx irx/filexio_irx.c filexio_irx
    DEPENDS $ENV{PS2SDK}/iop/irx/fileXio.irx
)

add_custom_command(
    OUTPUT irx/ps2fs_irx.c
    COMMAND bin2c $ENV{PS2SDK}/iop/irx/ps2fs.irx irx/ps2fs_irx.c ps2fs_irx
    DEPENDS $ENV{PS2SDK}/iop/irx/ps2fs.irx
)

add_custom_target(generate_irx_files
    DEPENDS
    irx/ps2dev9_irx.c
    irx/netman_irx.c
    irx/ps2ip_irx.c
    irx/smap_irx.c
    irx/atad_irx.c
    irx/iomanx_irx.c
    irx/filexio_irx.c
    irx/hdd_irx.c
    irx/ps2fs_irx.c
)

add_executable(http-server.elf main.c mongoose.c mongoose.h
    irx/ps2dev9_irx.c
    irx/netman_irx.c
    irx/ps2ip_irx.c
    irx/smap_irx.c
    irx/atad_irx.c
    irx/iomanx_irx.c
    irx/filexio_irx.c
    irx/hdd_irx.c
    irx/ps2fs_irx.c
    )

add_dependencies(http-server.elf generate_irx_files)

target_link_libraries(http-server.elf
    PRIVATE
    kernel
    ps2ip
    patches
    netman
    debug.so
    fileXio
    hdd)
