/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2018
*
*  TITLE:       CUI.H
*
*  VERSION:     1.12
*
*  DATE:        10 Jan 2018
*
*  Common header file for console ui.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

VOID cuiPrintText(
	_In_ HANDLE hOutConsole,
	_In_ LPWSTR lpText,
	_In_ BOOL ConsoleOutputEnabled,
	_In_ BOOL UseReturn
	);

VOID cuiPrintTextLastError(
    _In_ HANDLE hOutConsole,
    _In_ BOOL ConsoleOutputEnabled,
    _In_ BOOL UseReturn
    );
