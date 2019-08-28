#include "UnRootkitDriver.h"

NTSTATUS DriverEntry (	IN PDRIVER_OBJECT	pDriverObject,
						IN PUNICODE_STRING	pRegistryPath)
{

	NTSTATUS status;
	KdPrint(("Enter UnRootkit DriverEntry\n"));

	//ע�������������ú������
	pDriverObject->DriverUnload = UnRootkitDriverUnload;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UnRootkitDriverIOControl;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] =
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = 
	pDriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = UnRootkitDriverDispatchRoutine;
	//���������豸����

	status = UnRootkitDriverCreateDevice(pDriverObject);

	KdPrint(("Leave UnRootkit DriverEntry \n"));
	return status;
}

NTSTATUS UnRootkitDriverCreateDevice (IN PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS status;
	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;
	//�����豸����
	UNICODE_STRING devName;
	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&devName,L"\\Device\\UnRootkitDevice");
	//�����豸
	status = IoCreateDevice( pDriverObject,//һ��ָ����øú����������������.ÿһ����������������DriverEntry���������һ��ָ�����������������.WDM���ܺ͹�����������Ҳ�����ǵ�AddDevice���̽���һ��������������ָ��.
							sizeof(DEVICE_EXTENSION),//ָ����������Ϊ�豸��չ���������Ľṹ��Ĵ�С.
							&devName,/*(��ѡ�Ĳ���)ָ��һ�������β�İ���Unicode�ַ����Ļ�����,��������豸������,���ַ���������һ���������豸·����.WDM������������͹��������������ǵ��豸����û������.ע��:����豸��δ�ṩ(�����������NULL),IoCreateDevice�������豸���󽫲�����һ��DACL��֮�����.*/
							FILE_DEVICE_UNKNOWN,/*ָ��һ����һ��ϵͳ�����FILE_DEVICE_XXX����,����������豸������(��FILE_DEVICE_DISK,FILE_DEVICE_KEYBOARD��),��Ӧ�̶����һ�������豸������.*/
							0, /*ָ��һ������ϵͳ����ĳ���,������һ��,�ṩ�й�����������豸������Ϣ.���ڿ��ܵ��豸������Ϣ,��DEVICE_OBJECT�ṹ��.*/
							TRUE, //�Ƿ�Ϊ��ռ�豸��ΪTRUEʱ������ÿ�δ�һ�����豸�ľ����
							&pDevObj ); //����һ���豸����
	 
	if (!NT_SUCCESS(status))
		return status;
	pDevObj->Flags |= DO_BUFFERED_IO; //ָ������ģʽ��
	/*The operating system creates a nonpaged system buffer, equal in size to the application's buffer. 
	For write operations, the I/O manager copies user data into the system buffer before calling the driver stack. 
	For read operations, the I/O manager copies data from the system buffer into the application's buffer after the driver stack completes the requested operation.*/
	pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
	KeInitializeSpinLock(&pDevExt->Driver_Lock); //��ʼ���豸��չ���Զ��������
	pDevExt->pDevice = pDevObj;
	pDevExt->ustrDeviceName = devName;
	//������������pDevExt->ustrSymLinkName;�豸�����ܱ�RING3�µ�Ӧ�ó���ɼ������Դ���һ����������������RING3�´򿪺�ʹ�ø��豸��
	RtlInitUnicodeString(&symLinkName,L"\\??\\UnRootkitDevice");
	pDevExt->ustrSymLinkName = symLinkName;
	status = IoCreateSymbolicLink( &symLinkName,&devName );
	if (!NT_SUCCESS(status)) 
	{
		IoDeleteDevice( pDevObj );//The IoDeleteDevice routine removes a device object from the system, for example, when the underlying device is removed from the system.
		return status;
	}

	GetKernalModuleBaseAndSize();
	GetPspCidTable();

	return STATUS_SUCCESS;
}

VOID UnRootkitDriverUnload (IN PDRIVER_OBJECT pDriverObject)
{
	PDEVICE_OBJECT	pNextObj = pDriverObject->DeviceObject;
	PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pNextObj->DeviceExtension;
	UNICODE_STRING pLinkName = pDevExt->ustrSymLinkName;

	DbgPrint("Enter driver unload routine\n");
	IoDeleteSymbolicLink(&pLinkName);	//ɾ���豸�ķ�������
	IoDeleteDevice(pNextObj);			//ɾ���豸��When a driver calls IoDeleteDevice, the I/O manager deletes the target device object if there are no outstanding references to it. However, if any outstanding references remain, the I/O manager marks the device object as "delete pending" and deletes the device object when the references are released. 

	DbgPrint("Leave driver unload routine\n");
}

NTSTATUS UnRootkitDriverDispatchRoutine(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	KdPrint(("Enter dispatch routine\n"));
	// ���IRP
	pIrp->IoStatus.Status = status;		//����IRP��״̬Ϊ����ɹ�
	pIrp->IoStatus.Information = 0;		// ���ò������ֽ���Ϊ0������û��ʵ�����塣
	IoCompleteRequest( pIrp, IO_NO_INCREMENT ); //ָʾ����˸�IRP
	KdPrint(("Leave dispatch routine\n"));
	return status;
}

NTSTATUS UnRootkitDriverIOControl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG IoCode = stack->Parameters.DeviceIoControl.IoControlCode;

	ULONG OutPutBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
	PVOID OutPutBuffer = pIrp->AssociatedIrp.SystemBuffer;
	OUTBUF_PARAMETER  OutBufferParameter;

	ULONG info = 0;
	PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;

	PHANDLE_TABLE	CSRSSHandleTable;
	pFunWalkHandleTableCallBack pFunCallBack;

	DbgPrint("IOControl:Enter Io Control!\n");
	switch (IoCode)
	{
	case IOCTL_LISTPROCESS_HANDLE_TABLE_LIST:
		RtlZeroMemory(OutPutBuffer,OutPutBufferLength);
		ScanHandleTablesList(pIrp->AssociatedIrp.SystemBuffer,&info);
		//DbgPrint("0x%08x",*(PULONG)((ULONG)pCurrentProcess+0xc4));
		//ScanHandleTable((PHANDLE_TABLE)(*(PULONG)((ULONG)pCurrentProcess+0xc4)),pFunCallBack,NULL);
		break;
	case IOCTL_LISTPROCESS_PSPCIDTABLE:
		RtlZeroMemory(OutPutBuffer,OutPutBufferLength);
		OutBufferParameter.buffer = OutPutBuffer;			//ָ���������
		OutBufferParameter.ulMaxSize = OutPutBufferLength;	//���������ֽ�����
		OutBufferParameter.CurCount = 0;					//��ʼ������<--�����б��ڵĽ�����
		pFunCallBack = CollectProcessCallBack;
		ScanHandleTable(*PspCidTable,pFunCallBack,&OutBufferParameter);
		info = OutBufferParameter.CurCount * sizeof(MYPROCESSINFO);
		break;
	case IOCTL_LISTPROCESS_CSRSS_TABLE:
		RtlZeroMemory(OutPutBuffer,OutPutBufferLength);
		OutBufferParameter.buffer = OutPutBuffer;			//ָ���������
		OutBufferParameter.ulMaxSize = OutPutBufferLength;	//���������ֽ�����
		OutBufferParameter.CurCount = 0;					//��ʼ������<--�����б��ڵĽ�����
		CSRSSHandleTable = GetCsrssHandleTable();
		if (!CSRSSHandleTable)
		{
			DbgPrint("Error in get CSRSSHandleTable!\n");
			break;
		}
		pFunCallBack = CollectCsrssProcessCallBack;
		ScanHandleTable(CSRSSHandleTable,pFunCallBack,&OutBufferParameter);
		info = OutBufferParameter.CurCount * sizeof(MYPROCESSINFO);
		break;
	default:
		break;
	}
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = info;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);
	DbgPrint("IOControl:Leave Io Control!-----\n");
	return status;
}

NTSTATUS GetKernalModuleBaseAndSize()
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG                       n      = 0;
	ULONG                       i      = 0;
	PSYSTEM_MODULE_INFORMATION  module = NULL;
	PVOID                       pbuftmp    = NULL;
	PCSZ ModuleName;
	PHANDLE_TABLE	HandleTable;
	PLIST_ENTRY		HandleTableList;
	PLIST_ENTRY		CurrTable;

	DbgPrint("GetKernalModuleBaseAndSize:\tEnter Routine!");

	ZwQuerySystemInformation(SystemModuleInformation, &n, 0, &n);

	pbuftmp = ExAllocatePool(NonPagedPool, n);
	status	= ZwQuerySystemInformation(SystemModuleInformation, pbuftmp, n, NULL);
	module	= (PSYSTEM_MODULE_INFORMATION)((PULONG)pbuftmp + 1 );
	n		= *((PULONG)pbuftmp );
	ModuleName = module[0].ImageName+module[0].ModuleNameOffset;

	KernalModuleBase = (ULONG)(module[0].Base);
	KernalModuleSize = module[0].Size;

	HandleTable		= *(PHANDLE_TABLE *)((ULONG)PsGetCurrentProcess() + HandleTableOffset);
	HandleTableList = (PLIST_ENTRY)((ULONG)HandleTable + HandleTableListOffset);
	
	for (CurrTable = HandleTableList->Flink;CurrTable != HandleTableList;CurrTable = CurrTable->Flink)
	{
		if ((ULONG)CurrTable > KernalModuleBase && (ULONG)CurrTable < KernalModuleBase + KernalModuleSize)
		{
			HandleTableListHead = CurrTable;
			break;
		}
	}

	DbgPrint( "Module Information:\tbase:\t0x%08X Image Name :\t%s\n", module[1].Base,ModuleName);//
	ExFreePool(pbuftmp);

	DbgPrint("GetKernalModuleBaseAndSize:\tLeave Routine!");
	return status;
}

BOOL	ScanHandleTablesList(PVOID pOutputBuffer,PULONG pSizeReturn)
{
	NTSTATUS	status;
	PLIST_ENTRY	CurrTable;
	PEPROCESS	QuotaProcess;
	ULONG		ulProcessIndex = 0;
	PCHAR		pProcessName;
	STRING		TempAnsiString;
	UNICODE_STRING	TempUnicodeString;
	PMYPROCESSINFO	pListBase = (PMYPROCESSINFO)pOutputBuffer;

	PSECTION_OBJECT	pSection = NULL;
	PSEGMENT_OBJECT	pSegment = NULL;
	PCONTROL_AREA	pControlArea = NULL;
	PFILE_OBJECT	pFilePointer = NULL;
	ULONG			bytesIO = 0;

	UNICODE_STRING usDosName; 
	PUNICODE_STRING	pusTempImagePath;
	
	RtlInitUnicodeString(&TempUnicodeString, L"");

	for (CurrTable = HandleTableListHead->Flink;	CurrTable != HandleTableListHead;	CurrTable = CurrTable->Flink)
	{
		QuotaProcess = *(PEPROCESS *)((PUCHAR)CurrTable - HandleTableListOffset + QuotaProcessOffset);
		if (ulProcessIndex == 255)
		{
			DbgPrint("Max Process list count limit!\n");
		}
		
		if (QuotaProcess)
		{

			pProcessName = (PCHAR)((ULONG)QuotaProcess+EProcess_ImageFileName_offset);
			
			RtlInitAnsiString(&TempAnsiString,pProcessName);
			RtlAnsiStringToUnicodeString(&TempUnicodeString,&TempAnsiString,TRUE);

			RtlCopyMemory(pListBase[ulProcessIndex].uslpszExeFile,TempUnicodeString.Buffer,TempUnicodeString.Length);
			if (TempUnicodeString.Length <= MAX_PATH-2)
			{
				RtlZeroMemory(pListBase[ulProcessIndex].uslpszExeFile+TempUnicodeString.Length/2,2);
			}
			pListBase[ulProcessIndex].ProcessID			= *(PULONG)((ULONG)QuotaProcess+PIDOFFSET);
			pListBase[ulProcessIndex].cntThreads		= *(PULONG)((ULONG)QuotaProcess+ThreadsCountOffset);
			pListBase[ulProcessIndex].pcPriClassBase	= *(PUCHAR)((ULONG)QuotaProcess+PriorityClassOffset);
			
			pSection = (PSECTION_OBJECT)(*(PULONG)((ULONG)QuotaProcess+SectionObjectOffset));

			pControlArea = ((PSEGMENT)pSection->Segment)->ControlArea;
			pFilePointer = pControlArea->FilePointer;
			
			//pPeb = (PPEB)(*(PULONG)((ULONG)QuotaProcess+PebOffset));  //ʹ�����ַ���Ҫ�л����̿ռ�
			//pRtl_User_Process_Parameters = pPeb->ProcessParameters;
			//pusTempImagePath = &(pRtl_User_Process_Parameters->ImagePathName);
			//RtlCopyMemory(pListBase[ulProcessIndex].uslpszExePath,pusTempImagePath->Buffer,pusTempImagePath->Length);

			//EPROCESS->SectionObject(_SECTION_OBJECT)->Segment(_SEGMENT)->ControlArea (_CONTROL_AREA)->FilePointer( _FILE_OBJECT)
			status = ObReferenceObjectByPointer((PVOID)pFilePointer, 0, NULL, KernelMode); 
			RtlVolumeDeviceToDosName(pFilePointer->DeviceObject,&usDosName);
			pusTempImagePath = &(pFilePointer->FileName);
			DbgPrint("Process full path:%wZ%wZ\n",&usDosName,pusTempImagePath);
			RtlCopyMemory(pListBase[ulProcessIndex].uslpszExePath, usDosName.Buffer, usDosName.Length);
			RtlCopyMemory(pListBase[ulProcessIndex].uslpszExePath + usDosName.Length/2, pusTempImagePath->Buffer, pusTempImagePath->Length);
			ObDereferenceObject(pFilePointer);
			ulProcessIndex ++;
		}
		else
		{
			DbgPrint("Fail to get Process!!!\n");
		}

	}
	*pSizeReturn = ulProcessIndex * sizeof(MYPROCESSINFO);
	return TRUE;
}
//ScanHandleTable(*PspCidTable,pFunCallBack,NULL);
VOID ScanHandleTable(PHANDLE_TABLE HandleTable,	
					 pFunWalkHandleTableCallBack pFunCallBack,
					 PVOID pContext)
{
	int i, j, k;
	PHANDLE_TABLE_ENTRY Entry;
	PULONG pLevel2;
	PULONG pLevel3;
	PVOID	pValidObj;
	ULONG TableCode = HandleTable->TableCode & ~TABLE_LEVEL_MASK; //��һ���λ�ã���ַ����������
	
	switch (HandleTable->TableCode & TABLE_LEVEL_MASK)
	{
	case 0 :			//1��
			DbgPrint("ScanHandleTable 1st\n");
			for (i = 0; i < 0x200; i++)
			{
				Entry = (PHANDLE_TABLE_ENTRY)(TableCode+8*i);
				if ((ULONG)Entry>0x80000000 && MmIsAddressValid(Entry) && MmIsAddressValid(Entry->Object))
				{
					pValidObj = (PVOID)((ULONG)Entry->Object & ~XP_TABLE_ENTRY_LOCK_BIT);
					if((ULONG)pValidObj>0x80000000 && MmIsAddressValid(pValidObj))
					{
						if ((*pFunCallBack)(pContext, pValidObj))
						{
							return;
						}
					}
				}
			}
		break;

	case 1 :			//2��
		DbgPrint("ScanHandleTable 2nd\n");
		for (i = 0; i < 0x400; i++)
		{
			//�õ��ڶ����Ļ�ַ
			pLevel2 = (PULONG)((PULONG)TableCode)[i];
			if ((ULONG)pLevel2 == 0)
			{
				break;
			}
			//DbgPrint("==========> pLevel2 : 0x%08x",(ULONG)pLevel2);
			
			if ( (ULONG)pLevel2>0x80000000 && MmIsAddressValid((PVOID)pLevel2) )
			{
				for (j = 0; j < 0x200; j++)
				{
					Entry = (PHANDLE_TABLE_ENTRY)((ULONG)pLevel2+8*j);
					//DbgPrint("##===> Entry : 0x%08x",(ULONG)Entry);

					if ((ULONG)Entry>0x80000000 && MmIsAddressValid(Entry) && (MmIsAddressValid(Entry->Object)))
					{
						pValidObj = (PVOID)((ULONG)Entry->Object & ~XP_TABLE_ENTRY_LOCK_BIT);
						if((ULONG)pValidObj>0x80000000 && (MmIsAddressValid(pValidObj)))
						{
							//DbgPrint("==>Enter CollectProcessCallBack Entry->0x%08x\n",(ULONG)Entry);
							if ((*pFunCallBack)(pContext, pValidObj))//����ص�����TRUE������ѭ��
							{
								return;
							}
						}
					}
				}
			}
		}
		break;

	case 2 :
		DbgPrint("ScanHandleTable 3rd\n");
		for (i = 0; i < 0x400; i++)
		{
			pLevel2 = (PULONG)((PULONG)TableCode)[i];
			if ( (ULONG)pLevel2>0x80000000 && MmIsAddressValid((PVOID)pLevel2))
			{
				for (j = 0; j < 0x400; j++)
				{
					pLevel3 = (PULONG)pLevel2[j];
					if ( (ULONG)pLevel3>0x80000000 && MmIsAddressValid((PVOID)pLevel3))
					{
						for (k = 0; k < 200;k++)
						{
							Entry = (PHANDLE_TABLE_ENTRY)((ULONG)pLevel3+8*k);
							if ((ULONG)Entry>0x80000000 && MmIsAddressValid(Entry) && (MmIsAddressValid(Entry->Object)))
							{
								pValidObj = (PVOID)((ULONG)Entry->Object & ~XP_TABLE_ENTRY_LOCK_BIT);
								if((ULONG)pValidObj>0x80000000 && (MmIsAddressValid(pValidObj)))
								{
									if((*pFunCallBack)(pContext, pValidObj))
									{
										return;
									}
								}
							}
						}
					}
				}
			}
		}
		break;
	default:
		break;
	}
}

VOID GetPspCidTable()
{
	UNICODE_STRING usFunName;
	ULONG		   FunAddr;
	RtlInitUnicodeString(&usFunName,L"PsLookupProcessByProcessId");
	FunAddr = (ULONG)MmGetSystemRoutineAddress(&usFunName);
	PspCidTable = (PHANDLE_TABLE *)(*(PULONG)(FunAddr + offset_get_pspcid_table));
	/*
	8094f74a 8bff            mov     edi,edi
	8094f74c 55              push    ebp
	8094f74d 8bec            mov     ebp,esp
	8094f74f 51              push    ecx
	8094f750 53              push    ebx
	8094f751 56              push    esi
	8094f752 648b3524010000  mov     esi,dword ptr fs:[124h]
	8094f759 66ff4e70        dec     word ptr [esi+70h]
	8094f75d c745fc0d0000c0  mov     dword ptr [ebp-4],0C000000Dh
	8094f764 ff7508          push    dword ptr [ebp+8]
	8094f767 ff3540f28a80    push    dword ptr [nt!PspCidTable (808af240)]
	*/
	DbgPrint("PsLookupProcessByProcessId: 0x%08x,PspCidTable : 0x%08x",FunAddr,(ULONG)PspCidTable);
}

BOOL	DumpHanelTableCallBack(PVOID pContext,PVOID Object)//Object����objectHeader��Ķ�����
{
	POBJECT_HEADER	ObjectHeader = (POBJECT_HEADER)((ULONG)Object - 0x18);
	POBJECT_NAME	ObjectName;
	PUNICODE_STRING	pusProcessName;
	PUNICODE_STRING	pusObjectName;
	
	if ((ULONG)Object < 0x80000000 || !MmIsAddressValid(Object) || !MmIsAddressValid(ObjectHeader))
	{
		return FALSE;
	}

	if (ObjectHeader->Type == *PsProcessType)
	{
		DbgPrint("Object Type:Process; ProcessName: %s\n" ,(PCHAR)((ULONG)Object + EProcess_ImageFileName_offset));
	}
	else if (ObjectHeader->Type == *PsThreadType)
	{
		DbgPrint("No name Object 0x%08x Type:Thread\n",(ULONG)Object);
	}
	else if (ObjectHeader->Type == *PsJobType)
	{
		if (ObjectHeader->NameInfoOffset != 0)
		{
			ObjectName = (POBJECT_NAME)((ULONG)ObjectHeader - ObjectHeader->NameInfoOffset);
			pusObjectName = &(ObjectName->name);

			if (MmIsAddressValid(pusObjectName->Buffer))
			{
				DbgPrint(" Object Name:%wZ; Object Type:PsJobType;\n",pusObjectName);
			}
		}
		else
		{
			DbgPrint("No name Object 0x%08x Type:PsJobType;\n",(ULONG)Object);
		}
	}
	else if (ObjectHeader->Type == *IoDriverObjectType)
	{
		if (ObjectHeader->NameInfoOffset != 0)
		{
			ObjectName = (POBJECT_NAME)((ULONG)ObjectHeader - ObjectHeader->NameInfoOffset);
			pusObjectName = &(ObjectName->name);
			if (MmIsAddressValid(pusObjectName->Buffer))
			{
				DbgPrint("Object Name:%wZ; Object Type:IoDriverObjectType; \n",pusObjectName);
			}
		}
		else
		{
			DbgPrint("No name Object 0x%08x Type:IoDriverObjectType;\n",(ULONG)Object);
		}
	}
	else if (ObjectHeader->Type == *ExDesktopObjectType)
	{
		if (ObjectHeader->NameInfoOffset != 0)
		{
			ObjectName = (POBJECT_NAME)((ULONG)ObjectHeader - ObjectHeader->NameInfoOffset);
			pusObjectName = &(ObjectName->name);
			if (MmIsAddressValid(pusObjectName->Buffer))
			{
				DbgPrint("Object Name:%wZ; Object Type:ExDesktopObjectType; \n",pusObjectName);
			}
		}
		else
		{
			DbgPrint("No name Object 0x%08x Type:ExDesktopObjectType;\n",(ULONG)Object);
		}
	}
	else if (ObjectHeader->Type == *ExEventObjectType)
	{
		if (ObjectHeader->NameInfoOffset != 0)
		{
			ObjectName = (POBJECT_NAME)((ULONG)ObjectHeader - ObjectHeader->NameInfoOffset);
			pusObjectName = &(ObjectName->name);
			if (MmIsAddressValid(pusObjectName->Buffer))
			{
				DbgPrint("Object Name:%wZ; Object Type:ExEventObjectType; \n",pusObjectName);
			}
		}
		else
		{
			DbgPrint("No name Object 0x%08x Type:ExEventObjectType;\n",(ULONG)Object);
		}
	}
	else if (ObjectHeader->Type == *ExSemaphoreObjectType)
	{
		if (ObjectHeader->NameInfoOffset != 0)
		{
			ObjectName = (POBJECT_NAME)((ULONG)ObjectHeader - ObjectHeader->NameInfoOffset);
			pusObjectName = &(ObjectName->name);
			if (MmIsAddressValid(pusObjectName->Buffer))
			{
				DbgPrint("Object Name:%wZ; Object Type:ExSemaphoreObjectType; \n",pusObjectName);
			}
		}
		else
		{
			DbgPrint("No name Object 0x%08x Type:ExSemaphoreObjectType;\n",(ULONG)Object);
		}
	}
	else if (ObjectHeader->Type == *ExWindowStationObjectType)
	{
		if (ObjectHeader->NameInfoOffset != 0)
		{
			ObjectName = (POBJECT_NAME)((ULONG)ObjectHeader - ObjectHeader->NameInfoOffset);
			pusObjectName = &(ObjectName->name);
			if (MmIsAddressValid(pusObjectName->Buffer))
			{
				DbgPrint("Object Name:%wZ; Object Type:ExWindowStationObjectType; \n",pusObjectName);
			}
		}
		else
		{
			DbgPrint("No name Object 0x%08x Type:ExWindowStationObjectType;\n",(ULONG)Object);
		}
	}
	else if (ObjectHeader->Type == *IoAdapterObjectType)
	{
		if (ObjectHeader->NameInfoOffset != 0)
		{
			ObjectName = (POBJECT_NAME)((ULONG)ObjectHeader - ObjectHeader->NameInfoOffset);
			pusObjectName = &(ObjectName->name);
			if (MmIsAddressValid(pusObjectName->Buffer))
			{
				DbgPrint("Object Name:%wZ; Object Type:IoAdapterObjectType; \n",pusObjectName);
			}
		}
		else
		{
			DbgPrint("No name Object 0x%08x Type:IoAdapterObjectType;\n",(ULONG)Object);
		}
	}
	else if (ObjectHeader->Type == *IoDeviceHandlerObjectType)
	{
		if (ObjectHeader->NameInfoOffset != 0)
		{
			ObjectName = (POBJECT_NAME)((ULONG)ObjectHeader - ObjectHeader->NameInfoOffset);
			pusObjectName = &(ObjectName->name);
			if (MmIsAddressValid(pusObjectName->Buffer))
			{
				DbgPrint("Object Name:%wZ; Object Type:IoDeviceHandlerObjectType; \n",pusObjectName);
			}
		}
		else
		{
			DbgPrint("No name Object 0x%08x Type:IoDeviceHandlerObjectType;\n",(ULONG)Object);
		}
	}
	else if (ObjectHeader->Type == *IoDeviceObjectType)
	{
		if (ObjectHeader->NameInfoOffset != 0)
		{
			ObjectName = (POBJECT_NAME)((ULONG)ObjectHeader - ObjectHeader->NameInfoOffset);
			pusObjectName = &(ObjectName->name);
			if (MmIsAddressValid(pusObjectName->Buffer))
			{
				DbgPrint("Object Name:%wZ; Object Type:IoDeviceObjectType; \n",pusObjectName);
			}
		}
		else
		{
			DbgPrint("No name Object 0x%08x Type:IoDeviceObjectType;\n",(ULONG)Object);
		}
	}
	else if (ObjectHeader->Type == *IoDriverObjectType)
	{
		if (ObjectHeader->NameInfoOffset != 0)
		{
			ObjectName = (POBJECT_NAME)((ULONG)ObjectHeader - ObjectHeader->NameInfoOffset);
			pusObjectName = &(ObjectName->name);
			if (MmIsAddressValid(pusObjectName->Buffer))
			{
				DbgPrint("Object Name:%wZ; Object Type:IoDriverObjectType; \n",pusObjectName);
			}
		}
		else
		{
			DbgPrint("No name Object 0x%08x Type:IoDriverObjectType;\n",(ULONG)Object);
		}
	}
	else if (ObjectHeader->Type == *IoFileObjectType)
	{
		if (ObjectHeader->NameInfoOffset != 0)
		{
			ObjectName = (POBJECT_NAME)((ULONG)ObjectHeader - ObjectHeader->NameInfoOffset);
			pusObjectName = &(ObjectName->name);
			if (MmIsAddressValid(pusObjectName->Buffer))
			{
				DbgPrint("Object Name:%wZ; Object Type:IoFileObjectType; \n",pusObjectName);
			}
		}
		else
		{
			DbgPrint("No name Object 0x%08x Type:IoFileObjectType;\n",(ULONG)Object);
		}
	}
	else if (ObjectHeader->Type ==*LpcPortObjectType)
	{
		if (ObjectHeader->NameInfoOffset != 0)
		{
			ObjectName = (POBJECT_NAME)((ULONG)ObjectHeader - ObjectHeader->NameInfoOffset);
			pusObjectName = &(ObjectName->name);
			if (MmIsAddressValid(pusObjectName->Buffer))
			{
				DbgPrint("Object Name:%wZ; Object Type:LpcPortObjectType; \n",pusObjectName);
			}
		}
		else
		{
			DbgPrint("No name Object 0x%08x Type:LpcPortObjectType;\n",(ULONG)Object);
		}
	}
	else if (ObjectHeader->Type == *MmSectionObjectType)
	{
		if (ObjectHeader->NameInfoOffset != 0)
		{
			ObjectName = (POBJECT_NAME)((ULONG)ObjectHeader - ObjectHeader->NameInfoOffset);
			pusObjectName = &(ObjectName->name);
			if (MmIsAddressValid(pusObjectName->Buffer))
			{
				DbgPrint("Object Name:%wZ; Object Type:MmSectionObjectType; \n",pusObjectName);
			}
		}
		else
		{
			DbgPrint("No name Object 0x%08x Type:MmSectionObjectType;\n",(ULONG)Object);
		}
	}
	else if (ObjectHeader->Type == *SeTokenObjectType)
	{
		if (ObjectHeader->NameInfoOffset != 0)
		{
			ObjectName = (POBJECT_NAME)((ULONG)ObjectHeader - ObjectHeader->NameInfoOffset);
			pusObjectName = &(ObjectName->name);
			if (MmIsAddressValid(pusObjectName->Buffer))
			{
				DbgPrint("Object Name:%wZ; Object Type:SeTokenObjectType; \n",pusObjectName);
			}
		}
		else
		{
			DbgPrint("No name Object 0x%08x Type:SeTokenObjectType;\n",(ULONG)Object);
		}
	}
	else
	{
		DbgPrint("Unknown Type Object 0x%08x\n",(ULONG)Object);
	}

	return FALSE;
}

//ȫ������False�Ա�������
//����CidTable�Ļص�����
//����Object����ǽ��̻������߳���������ӵ��б� 
//ע��Object�Ǵ�������
BOOL		CollectProcessCallBack(IN OUT PVOID pContext,IN PVOID Object)
{		
	NTSTATUS		status;
	ULONG			PID;	
	BOOL			isExist = FALSE;
	ULONG			i;
	PCHAR			pProcessName;  //PEPROCESS + 0X174
	STRING			ProcessName;	//ANSI
	UNICODE_STRING	usProcessName;	//UNICODE
	UNICODE_STRING	usDosName;		//DEVICE TO DOS NAME
	PUNICODE_STRING	pusTempImagePath = NULL;
	UNICODE_STRING	usTemp;

	POBJECT_HEADER	ObjectHeader = (POBJECT_HEADER)((ULONG)Object - 0x18);
	POUTBUF_PARAMETER  pOutBufferParameter = (POUTBUF_PARAMETER)pContext;
	PEPROCESS		pEprocess;
	PMYPROCESSINFO	pListBase = (PMYPROCESSINFO)pOutBufferParameter->buffer;
	
	PSECTION_OBJECT	pSection = NULL;
	PSEGMENT_OBJECT	pSegment = NULL;
	PCONTROL_AREA	pControlArea = NULL;
	PFILE_OBJECT	pFilePointer = NULL;
	
	RtlInitUnicodeString(&usProcessName,L"");
	RtlInitUnicodeString(&usDosName,L"");
	
	//DbgPrint("CollectProcessCallBack: Enter Routine;\n");
	if ((ULONG)Object < 0x80000000 || !MmIsAddressValid(Object) || !MmIsAddressValid(ObjectHeader))
	{
		DbgPrint("CollectProcessCallBack: wrong parameters!");
		return FALSE;
	}

	if (pOutBufferParameter->CurCount == MAX_PROCESS_COUNT-1)
	{
		DbgPrint("Max Process list count limit!\n");
		return FALSE;
	}

	if (ObjectHeader->Type == *PsProcessType)			//process���Ͷ���
	{
		pEprocess = (PEPROCESS)Object;
	}
	else if (ObjectHeader->Type == *PsThreadType)
	{
		pEprocess = (PEPROCESS)(*(PULONG)((ULONG)Object+OffsetPEP));//thread���Ͷ���
	}
	else
	{
		pEprocess = NULL;
		return	FALSE;
	}

	if (pEprocess)
	{
		PID = *(PULONG)((ULONG)pEprocess+PIDOFFSET);
		isExist	= FALSE;

		for (i=0; i<pOutBufferParameter->CurCount; i++)//���������Ƿ��Ѿ��д˽���
		{
			if (pListBase[i].ProcessID == PID)
			{
				isExist = TRUE;
			}
		}
		if (isExist)
		{
			return FALSE;							//����Ѿ����ڣ�����������
		}

		pListBase[pOutBufferParameter->CurCount].ProcessID = *(PULONG)((ULONG)pEprocess+PIDOFFSET);
		if (pListBase[pOutBufferParameter->CurCount].ProcessID == 4) //system
		{
			pProcessName = "System";
			RtlInitAnsiString(&ProcessName,pProcessName);
			RtlAnsiStringToUnicodeString(&usProcessName,&ProcessName,TRUE);

			RtlCopyMemory(pListBase[pOutBufferParameter->CurCount].uslpszExeFile,
						usProcessName.Buffer,
						usProcessName.Length);
			pListBase[pOutBufferParameter->CurCount].cntThreads		= 0;
			pListBase[pOutBufferParameter->CurCount].pcPriClassBase	= 0;
			RtlInitUnicodeString(&usTemp,L"System");
			RtlCopyMemory(pListBase[pOutBufferParameter->CurCount].uslpszExePath, usTemp.Buffer, usTemp.Length);
			pOutBufferParameter->CurCount ++; 
			return FALSE;
		}
		pProcessName = (PCHAR)((ULONG)pEprocess+EProcess_ImageFileName_offset);

		RtlInitAnsiString(&ProcessName,pProcessName);
		RtlAnsiStringToUnicodeString(&usProcessName,&ProcessName,TRUE);

		RtlCopyMemory(pListBase[pOutBufferParameter->CurCount].uslpszExeFile,
						usProcessName.Buffer,
						usProcessName.Length);

		if (usProcessName.Length <=  MAX_PATH -2)
		{
			RtlZeroMemory(pListBase[pOutBufferParameter->CurCount].uslpszExeFile+usProcessName.Length/2, 2);
		}
		pListBase[pOutBufferParameter->CurCount].cntThreads		= *(PULONG)((ULONG)pEprocess+ThreadsCountOffset);
		pListBase[pOutBufferParameter->CurCount].pcPriClassBase	= *(PUCHAR)((ULONG)pEprocess+PriorityClassOffset);

		pSection = (PSECTION_OBJECT)(*(PULONG)((ULONG)pEprocess+SectionObjectOffset));
		if (pSection && MmIsAddressValid(pSection))
		{
			if ((PSEGMENT)pSection->Segment && MmIsAddressValid(((PSEGMENT)pSection->Segment)))
			{

				pControlArea = ((PSEGMENT)pSection->Segment)->ControlArea;
				if (pControlArea && MmIsAddressValid(pControlArea))
				{
					pFilePointer = pControlArea->FilePointer;
					if (pFilePointer && MmIsAddressValid(pControlArea))
					{
						status = ObReferenceObjectByPointer((PVOID)pFilePointer, 0, NULL, KernelMode); 
						RtlVolumeDeviceToDosName(pFilePointer->DeviceObject,&usDosName);
						pusTempImagePath = &(pFilePointer->FileName);
						DbgPrint("CollectProcessCallBack:-->Process full path:%wZ%wZ\n",&usDosName,pusTempImagePath);
						RtlCopyMemory(pListBase[pOutBufferParameter->CurCount].uslpszExePath, usDosName.Buffer, usDosName.Length);
						RtlCopyMemory(pListBase[pOutBufferParameter->CurCount].uslpszExePath + usDosName.Length/2, pusTempImagePath->Buffer, pusTempImagePath->Length);
						ObDereferenceObject(pFilePointer);
						pOutBufferParameter->CurCount ++; 
					}
					/*pPeb = (PPEB)(*(PULONG)((ULONG)QuotaProcess+PebOffset));  //ʹ�����ַ���Ҫ�л����̿ռ�
					pRtl_User_Process_Parameters = pPeb->ProcessParameters;
					pusTempImagePath = &(pRtl_User_Process_Parameters->ImagePathName);
					RtlCopyMemory(pListBase[ulProcessIndex].uslpszExePath,pusTempImagePath->Buffer,pusTempImagePath->Length);
					EPROCESS->SectionObject(_SECTION_OBJECT)->Segment(_SEGMENT)->ControlArea (_CONTROL_AREA)->FilePointer( _FILE_OBJECT)*/
				}
			}
		}
	}
	return FALSE;
}

//��ȡCSRSS.EXE HandleTable��ַ
//�޲���
//����HandleTable��ַ
PHANDLE_TABLE	GetCsrssHandleTable()
{

	ULONG eproc=0x0;
	int current_PID=0;
	int start_PID=0;
	int WalkProcessCount = 0;	//����������
	PLIST_ENTRY plist_active_procs;

	ULONG	pEProcess;
	PTSTR	ProcessName;
	STRING	str_ProcName;
	STRING	asProcessToFind;
	
	PHANDLE_TABLE	CsrssHandleTable = NULL;

	RtlInitAnsiString(&asProcessToFind,"csrss.exe");
	eproc		=	(ULONG)PsGetCurrentProcess();	//��ȡ��ǰ���̵�PEPROCESS��ַ(ָ��)
	start_PID	=	*((int *)(eproc+PIDOFFSET));	//��ȡ��ǰ���̵�PID
	current_PID	=	start_PID;						//��ʼPID����ǰ����PID	

	DbgPrint("Enter  GetCsrssHandleTable routine.---\n");
	while(1)
	{
		if((WalkProcessCount >= 1)&&(start_PID == current_PID))//�����ǰPID���ڿ�ʼ����PID˵������������
		{													//���Ե�һ��
			DbgPrint("GetCsrssHandleTable:Not find Csrss.exe!\n");
			return NULL;
		}
		else
		{			
			pEProcess = eproc;
			ProcessName = (PTSTR)(pEProcess+EProcess_ImageFileName_offset);
			RtlInitAnsiString(&str_ProcName,ProcessName);
			if (!RtlCompareString(&str_ProcName,&asProcessToFind,TRUE))//�ҵ���CSRSS.EXE
			{
				CsrssHandleTable = (PHANDLE_TABLE)(*(PULONG)((ULONG)pEProcess+HandleTableOffset));
				DbgPrint("Find CSRSS.EXE and Get handle table 0x%08x;\n",(ULONG)CsrssHandleTable);
				return CsrssHandleTable;
			}
			
			plist_active_procs = (PLIST_ENTRY)(eproc+FLINKOFFSET);//FLINKƫ��FLINKOFFSET 0x88
			eproc = (ULONG)(plist_active_procs->Flink) - FLINKOFFSET;	//��һ��FLINK����FLINKOFFSETȡ��һ��PEPROCESS��ַ(ָ��)

			current_PID = *((int *)(eproc+PIDOFFSET));			//��ȡ��һ����PID
			if (current_PID < 0) //system handle
			{
				current_PID = 0;
			}
			WalkProcessCount ++;
		}
	}
}

//�ռ�CSRSS.EXE�����е�PROCESS
//�������pContext ���Զ������
//�������Object	��CSRSS.EXE�������ľ����Ӧ�Ķ��󣬸ö����������ͷ���֣�PspCidTable��Ķ��󲻰�������ͷ��
BOOL		CollectCsrssProcessCallBack(IN OUT PVOID pContext,IN PVOID Object)
{
	BOOL	bRet = FALSE;
	PVOID	CsrssHandleTableObject = (PVOID)((ULONG)Object + 0x18);//��ȡ������

	bRet = CollectProcessCallBack(pContext,CsrssHandleTableObject);//����ͨ�ñ��������Ļص�
	if (bRet)
	{
		return	TRUE;
	}
	else
	{
		return	FALSE;
	}
}

//DUMP CSRSS.EXE�����е�PROCESS��Ϣ
//�������pContext ���Զ������
//�������Object	��CSRSS.EXE�������ľ����Ӧ�Ķ��󣬸ö����������ͷ���֣�PspCidTable��Ķ��󲻰�������ͷ��
BOOL		DumpCsrssHanelTableCallBack(IN OUT PVOID pContext,IN PVOID Object)
{
	BOOL	bRet = FALSE;
	PVOID	CsrssHandleTableObject = (PVOID)((ULONG)Object + 0x18);
	bRet = DumpHanelTableCallBack(pContext,CsrssHandleTableObject);
	if (bRet)
	{
		return	TRUE;
	}
	else
	{
		return	FALSE;
	}
}
