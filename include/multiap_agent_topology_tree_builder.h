/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#ifndef MULTIAP_AGENT_TOP_TREE_BUILDER_H
#define MULTIAP_AGENT_TOP_TREE_BUILDER_H

#include "map_common_defines.h"
#include "map_data_model.h"
#include <stdint.h>

/** @brief Intialize Agent's topology tree.
*
*	This will be used to intialize the internally maintained
*	topology tree data structures
*
*	@return The status code 0-success, -ve for failure
*/
int8_t init_agent_topology_tree();

/** @brief This function will update topology
*   tree to add the agent's neighbours.
*
*   This will be used to add the immediate neighbors of agent
*   as the children in topology tree data structures.
*
*   @return None
*/
void map_add_neighbour_of_agent(map_ale_info_t *ale);

#endif //MULTIAP_AGENT_TOP_TREE_BUILDER_H

