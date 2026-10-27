/** @file
  Publish the FAT initrd from a Mu-Silicium FDT handoff as a read-only block device.

  SPDX-License-Identifier: BSD-2-Clause
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/FdtLib.h>
#include <Library/HobLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePath.h>

// Mu-Silicium SEC stores the incoming x0 value in this HOB as a UINT64.
STATIC CONST EFI_GUID mEntryArgHobGuid = {
  0xDAEE82E6, 0x8090, 0x4E72, { 0xBF, 0xB9, 0x78, 0xC1, 0x3C, 0xD4, 0xE3, 0x59 }
};

// Optional BootShim transport for Android bootloaders that expose vendor_boot's
// ramdisk in the FDT instead of the generic ramdisk supplied to fastboot boot.
STATIC CONST EFI_GUID mEmbeddedPayloadHobGuid = {
  0xA8E7F3A4, 0xE28B, 0x4E66, { 0xA4, 0x6E, 0x99, 0x72, 0x78, 0x65, 0x72, 0x31 }
};

typedef struct {
  UINT64  Base;
  UINT64  Size;
} EMBEDDED_PAYLOAD;

STATIC
UINT64
ReadCells (
  IN CONST VOID  *Data,
  IN UINT32      Cells
  )
{
  if (Cells == 2) {
    return Fdt64ToCpu (ReadUnaligned64 (Data));
  }

  return Fdt32ToCpu (ReadUnaligned32 (Data));
}

#define RAM_BLOCK_SIZE  512

STATIC
BOOLEAN
Fat32PayloadSize (
  IN  CONST UINT8  *BootSector,
  IN  UINT64       Available,
  OUT UINT64       *PayloadSize
  )
{
  UINT16  BytesPerSector;
  UINT8   SectorsPerCluster;
  UINT16  ReservedSectors;
  UINT8   FatCount;
  UINT32  FatSectors;
  UINT32  TotalSectors;
  UINT64  Size;

  if ((Available < RAM_BLOCK_SIZE) ||
      (BootSector[510] != 0x55) || (BootSector[511] != 0xAA) ||
      (CompareMem (BootSector + 82, "FAT32   ", 8) != 0))
  {
    return FALSE;
  }

  BytesPerSector    = ReadUnaligned16 ((CONST UINT16 *)(BootSector + 11));
  SectorsPerCluster = BootSector[13];
  ReservedSectors   = ReadUnaligned16 ((CONST UINT16 *)(BootSector + 14));
  FatCount          = BootSector[16];
  TotalSectors      = ReadUnaligned32 ((CONST UINT32 *)(BootSector + 32));
  FatSectors        = ReadUnaligned32 ((CONST UINT32 *)(BootSector + 36));

  if ((BytesPerSector != RAM_BLOCK_SIZE) ||
      (SectorsPerCluster == 0) || ((SectorsPerCluster & (SectorsPerCluster - 1)) != 0) ||
      (ReservedSectors == 0) || ((FatCount != 1) && (FatCount != 2)) ||
      (TotalSectors == 0) || (FatSectors == 0) ||
      ((UINT64)ReservedSectors + (UINT64)FatCount * FatSectors >= TotalSectors))
  {
    return FALSE;
  }

  Size = (UINT64)TotalSectors * BytesPerSector;
  if ((Size != Available) || ((Size % RAM_BLOCK_SIZE) != 0)) {
    return FALSE;
  }

  *PayloadSize = Size;
  return TRUE;
}

#pragma pack(1)
typedef struct {
  VENDOR_DEVICE_PATH          Vendor;
  EFI_DEVICE_PATH_PROTOCOL    End;
} RAM_BLOCK_DEVICE_PATH;
#pragma pack()

STATIC RAM_BLOCK_DEVICE_PATH  mDevicePath = {
  {
    { HARDWARE_DEVICE_PATH, HW_VENDOR_DP, { (UINT8)sizeof (VENDOR_DEVICE_PATH), (UINT8)(sizeof (VENDOR_DEVICE_PATH) >> 8) } },
    { 0xA9C6827C, 0x1BD8, 0x410C, { 0x88, 0x5A, 0xC4, 0x65, 0x00, 0xF7, 0xD8, 0x36 } }
  },
  { END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, { sizeof (EFI_DEVICE_PATH_PROTOCOL), 0 } }
};

STATIC UINT8                    *mRamBase;
STATIC EFI_BLOCK_IO_MEDIA       mMedia;

STATIC
EFI_STATUS
EFIAPI
RamBlockReset (
  IN EFI_BLOCK_IO_PROTOCOL  *This,
  IN BOOLEAN                ExtendedVerification
  )
{
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
RamBlockRead (
  IN  EFI_BLOCK_IO_PROTOCOL  *This,
  IN  UINT32                 MediaId,
  IN  EFI_LBA                Lba,
  IN  UINTN                  BufferSize,
  OUT VOID                   *Buffer
  )
{
  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (MediaId != mMedia.MediaId) {
    return EFI_MEDIA_CHANGED;
  }

  if ((BufferSize % RAM_BLOCK_SIZE) != 0) {
    return EFI_BAD_BUFFER_SIZE;
  }

  if ((Lba > mMedia.LastBlock) || ((BufferSize / RAM_BLOCK_SIZE) > (mMedia.LastBlock + 1 - Lba))) {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem (Buffer, mRamBase + Lba * RAM_BLOCK_SIZE, BufferSize);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
RamBlockWrite (
  IN EFI_BLOCK_IO_PROTOCOL  *This,
  IN UINT32                 MediaId,
  IN EFI_LBA                Lba,
  IN UINTN                  BufferSize,
  IN VOID                   *Buffer
  )
{
  return EFI_WRITE_PROTECTED;
}

STATIC
EFI_STATUS
EFIAPI
RamBlockFlush (
  IN EFI_BLOCK_IO_PROTOCOL  *This
  )
{
  return EFI_SUCCESS;
}

STATIC EFI_BLOCK_IO_PROTOCOL  mBlockIo = {
  EFI_BLOCK_IO_PROTOCOL_REVISION,
  &mMedia,
  RamBlockReset,
  RamBlockRead,
  RamBlockWrite,
  RamBlockFlush
};

STATIC
VOID
PublishInitrd (
  IN CONST VOID  *Fdt
  )
{
  EFI_STATUS  Status;
  INT32       Chosen;
  CONST VOID  *StartProp;
  CONST VOID  *EndProp;
  INT32       StartLength;
  INT32       EndLength;
  UINT64      Start;
  UINT64      End;
  EFI_HANDLE  Handle;

  Chosen = FdtPathOffset (Fdt, "/chosen");
  if (Chosen < 0) {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: no /chosen\n"));
    return;
  }

  StartProp = FdtGetProp (Fdt, Chosen, "linux,initrd-start", &StartLength);
  EndProp   = FdtGetProp (Fdt, Chosen, "linux,initrd-end", &EndLength);
  if ((StartProp == NULL) || (EndProp == NULL) ||
      ((StartLength != 4) && (StartLength != 8)) || ((EndLength != 4) && (EndLength != 8)))
  {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: no initrd in /chosen\n"));
    return;
  }

  Start = ReadCells (StartProp, StartLength / 4);
  End   = ReadCells (EndProp, EndLength / 4);
  if ((End <= Start) || (((End - Start) % RAM_BLOCK_SIZE) != 0)) {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: initrd 0x%lx-0x%lx is not a whole number of sectors\n", Start, End));
    return;
  }

  mRamBase                = (UINT8 *)(UINTN)Start;
  mMedia.MediaId          = 1;
  mMedia.RemovableMedia   = FALSE;
  mMedia.MediaPresent     = TRUE;
  mMedia.LogicalPartition = FALSE;
  mMedia.ReadOnly         = TRUE;
  mMedia.WriteCaching     = FALSE;
  mMedia.BlockSize        = RAM_BLOCK_SIZE;
  mMedia.IoAlign          = 1;
  mMedia.LastBlock        = (End - Start) / RAM_BLOCK_SIZE - 1;

  Handle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiDevicePathProtocolGuid,
                  &mDevicePath,
                  &gEfiBlockIoProtocolGuid,
                  &mBlockIo,
                  NULL
                  );
  DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: initrd block device 0x%lx size 0x%lx %r\n", Start, End - Start, Status));
}

EFI_STATUS
EFIAPI
UniXNURamDiskDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_HOB_GUID_TYPE  *Hob;
  EMBEDDED_PAYLOAD   *EmbeddedPayload;
  UINT64             Dtb;

  Hob = GetFirstGuidHob (&mEmbeddedPayloadHobGuid);
  if ((Hob != NULL) && (GET_GUID_HOB_DATA_SIZE (Hob) >= sizeof (EMBEDDED_PAYLOAD))) {
    EmbeddedPayload = (EMBEDDED_PAYLOAD *)GET_GUID_HOB_DATA (Hob);
    if ((EmbeddedPayload->Size == 0) ||
        !Fat32PayloadSize (
           (CONST UINT8 *)(UINTN)EmbeddedPayload->Base,
           EmbeddedPayload->Size,
           &Dtb
           ))
    {
      DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: embedded payload is not a valid FAT32 volume\n"));
      return EFI_COMPROMISED_DATA;
    }

    mRamBase                = (UINT8 *)(UINTN)EmbeddedPayload->Base;
    mMedia.MediaId          = 1;
    mMedia.RemovableMedia   = FALSE;
    mMedia.MediaPresent     = TRUE;
    mMedia.LogicalPartition = FALSE;
    mMedia.ReadOnly         = TRUE;
    mMedia.WriteCaching     = FALSE;
    mMedia.BlockSize        = RAM_BLOCK_SIZE;
    mMedia.IoAlign          = 1;
    mMedia.LastBlock        = EmbeddedPayload->Size / RAM_BLOCK_SIZE - 1;
    ImageHandle = NULL;
    return gBS->InstallMultipleProtocolInterfaces (
                  &ImageHandle,
                  &gEfiDevicePathProtocolGuid,
                  &mDevicePath,
                  &gEfiBlockIoProtocolGuid,
                  &mBlockIo,
                  NULL
                  );
  }

  Hob = GetFirstGuidHob (&mEntryArgHobGuid);
  if (Hob == NULL) {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: no entry argument HOB\n"));
    return EFI_SUCCESS;
  }

  if (GET_GUID_HOB_DATA_SIZE (Hob) < sizeof (UINT64)) {
    return EFI_COMPROMISED_DATA;
  }

  Dtb = ReadUnaligned64 ((CONST UINT64 *)GET_GUID_HOB_DATA (Hob));
  if ((Dtb == 0) || ((Dtb & 3) != 0) || (FdtCheckHeader ((VOID *)(UINTN)Dtb) != 0)) {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: x0 0x%lx is not a device tree\n", Dtb));
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: device tree at 0x%lx, %u bytes\n", Dtb, (UINT32)FdtTotalSize ((VOID *)(UINTN)Dtb)));

  PublishInitrd ((VOID *)(UINTN)Dtb);
  return EFI_SUCCESS;
}
