/***************************************************************************
 *   module.h                                                              *
 *   Copyright (C) 2006 by foofus.net                                      *
 *   fizzgig@foofus.net                                                    *
 *                                                                         *
 *   Common header file for all loadable modules                           *
 *                                                                         *
 *   CHANGE LOG                                                            *
 *   02/18/2004 -- Created by Foofus                                       *
 *   04/05/2005 -- (fizzgig) Added include for medusa-net                  *
 *   04/12/2005 -- Final "alpha" implementation                            *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License version 2,       *
 *   as published by the Free Software Foundation                          *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   http://www.gnu.org/licenses/gpl.txt                                   *
 *                                                                         *
 *   This program is released under the GPL with the additional exemption  *
 *   that compiling, linking, and/or using OpenSSL is allowed.             *
 *                                                                         *
 ***************************************************************************/


/*	See to it that we only include this file once	*/
#ifndef	__MODULE_H__
#define	__MODULE_H__	1

/*  Includes */
#include "../medusa-net.h"
#include "../medusa.h"
#include "../medusa-trace.h"
#include "../medusa-utils.h"

/*	Symbols	*/
#define	MODULE_EXTENSION	".mod"

extern void initConnectionParams(sLogin* pLogin, sConnectParams* pParams);

/*	Prototypes for required functions	*/
int getParamNumber( );	/* Dictates how many parameters the module allows */
void summaryUsage( char **szUsage );	/*	Allocates and populates a string with brief descriptive info	*/
void showUsage( );	 /*	Displays module usage information	*/
int go( sLogin* logins, int argc, char *argv[] );	/*	Launches the module with available parameters	*/

/*	Typedefs for function pointers	*/
typedef int (*function_getParamNumber)( );
typedef void (*function_summaryUsage)( char** );
typedef void (*function_showUsage)( );
typedef int (*function_go)( sLogin*, int, char*[] );

#endif	/*	(was this file already included?)	*/

