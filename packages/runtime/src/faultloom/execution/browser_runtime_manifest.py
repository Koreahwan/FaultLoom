from __future__ import annotations

from enum import StrEnum, unique
from typing import Annotated, Final

from pydantic import Field

from faultloom_protocol.base import Sha256Digest

from .contracts import ExecutionModel


@unique
class ChromiumAssetName(StrEnum):
    ABOUT = "ABOUT"
    CHROME = "chrome"
    CHROME_WRAPPER = "chrome-wrapper"
    CHROME_100_PERCENT = "chrome_100_percent.pak"
    CHROME_200_PERCENT = "chrome_200_percent.pak"
    CHROME_CRASHPAD_HANDLER = "chrome_crashpad_handler"
    CHROME_SANDBOX = "chrome_sandbox"
    DEB_DEPS = "deb.deps"
    ICU_DATA = "icudtl.dat"
    LIB_EGL = "libEGL.so"
    LIB_GLES = "libGLESv2.so"
    LIB_SWIFTSHADER = "libvk_swiftshader.so"
    LIB_VULKAN = "libvulkan.so.1"
    PRODUCT_LOGO = "product_logo_48.png"
    RESOURCES = "resources.pak"
    RPM_DEPS = "rpm.deps"
    V8_CONTEXT_SNAPSHOT = "v8_context_snapshot.bin"
    VULKAN_CONFIG = "vk_swiftshader_icd.json"


class ChromiumRuntimeAsset(ExecutionModel):
    name: ChromiumAssetName
    digest: Sha256Digest
    byte_length: Annotated[int, Field(gt=0)]
    executable: bool


PINNED_CHROMIUM_RUNTIME_ASSETS: Final[tuple[ChromiumRuntimeAsset, ...]] = (
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.ABOUT,
        digest="sha256:34d078ce3003087a8374e7c6156fda374769b8047d6ddaf419d66414aa48edfb",
        byte_length=248,
        executable=False,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.CHROME,
        digest="sha256:888bc05a6af72381dd9e45777a0a65569078a732d8c71f194f2789fdbfc6ad53",
        byte_length=290_540_872,
        executable=True,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.CHROME_WRAPPER,
        digest="sha256:24c1cfddcd206a86281008e7eed38109344ef34cd88d61902a9befd520a5571c",
        byte_length=4_510,
        executable=True,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.CHROME_100_PERCENT,
        digest="sha256:ec2c300171ee5ba6f2ecb659e428007269319ea82201e71cfe8c738a7eadcfaa",
        byte_length=698_861,
        executable=False,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.CHROME_200_PERCENT,
        digest="sha256:f92ee8c101dab4130d5ed447a02d66cabf6344cb523bdf90bf0479ffa7965c1f",
        byte_length=1_197_634,
        executable=False,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.CHROME_CRASHPAD_HANDLER,
        digest="sha256:2a36f395685421476e51b8867b1397845d83d24e85312afffe8ecee92f61f8d1",
        byte_length=1_943_256,
        executable=True,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.CHROME_SANDBOX,
        digest="sha256:18391bf9d217ddbde9956347cbb1346d2808a73ade4baa3f88a610447cf946b4",
        byte_length=15_232,
        executable=True,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.DEB_DEPS,
        digest="sha256:58b1812937bc63f4112f3ab59cbec7bf3d4c2930869f3b0ccba91b7aa62367a7",
        byte_length=659,
        executable=False,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.ICU_DATA,
        digest="sha256:9f48c7f9c7c94d516a14870707e910ab94d75ae640ff6842c4af53276cd26ebe",
        byte_length=10_876_560,
        executable=False,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.LIB_EGL,
        digest="sha256:98a6d29c77efed16beb6a55e6d90d887a6b3667a68f2721435acf3f9745d2fa7",
        byte_length=226_968,
        executable=True,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.LIB_GLES,
        digest="sha256:ad4c39656558248361c48a5867c064b95a76f0832f3469229b050e900adb76b1",
        byte_length=226_968,
        executable=True,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.LIB_SWIFTSHADER,
        digest="sha256:29f1cf20bcb19951137efc13dcbb919a480a5ce94ac1944ab8b58c27b3ccfef1",
        byte_length=4_037_592,
        executable=True,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.LIB_VULKAN,
        digest="sha256:041322175839ff3b0d0d155afb3c2ff6e974560c10df616aba4b499b2b918b4b",
        byte_length=660_576,
        executable=True,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.PRODUCT_LOGO,
        digest="sha256:42142312e7fa9221b8ad0790c1ecec86edd35468724ec103ec27e1125a43c8b2",
        byte_length=2_772,
        executable=False,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.RESOURCES,
        digest="sha256:7a1f91b6ffbe7fb2042a658e0d509ce9f772370097b6de916066e773df9b6b3f",
        byte_length=21_335_087,
        executable=False,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.RPM_DEPS,
        digest="sha256:e159e9d987aced7d5af081319967f702ee993b04ad49e1ca893264e9fbead66c",
        byte_length=2_519,
        executable=False,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.V8_CONTEXT_SNAPSHOT,
        digest="sha256:96f0afb72604a97d4c899857da0a838e40e7a6913b17568b1d5396bc02e9cd88",
        byte_length=740_440,
        executable=False,
    ),
    ChromiumRuntimeAsset(
        schema_version="0.1.0",
        name=ChromiumAssetName.VULKAN_CONFIG,
        digest="sha256:c9eef28b6b984fec220ef0abfecc40b502d46946706e47bfe97707027cb818bd",
        byte_length=107,
        executable=False,
    ),
)
