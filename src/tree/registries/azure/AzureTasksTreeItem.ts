/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.md in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { ContainerRegistryManagementModels as AcrModels } from "@azure/arm-containerregistry"; // These are only dev-time imports so don't need to be lazy
import { ThemeIcon } from "vscode";
import { AzExtParentTreeItem, AzExtTreeItem, IActionContext } from "vscode-azureextensionui";
import { localize } from '../../../localize';
import { OpenUrlTreeItem } from "../../OpenUrlTreeItem";
import { AzureRegistryTreeItem } from "./AzureRegistryTreeItem";
import { AzureTaskTreeItem } from "./AzureTaskTreeItem";

export class AzureTasksTreeItem extends AzExtParentTreeItem {
    public static contextValue: string = 'azureTasks';
    public contextValue: string = AzureTasksTreeItem.contextValue;
    public label: string = 'Tasks';
    public childTypeLabel: string = 'task';
    public parent: AzureRegistryTreeItem;

    private _nextLink: string | undefined;

    public constructor(parent: AzureRegistryTreeItem) {
        super(parent);
        this.iconPath = new ThemeIcon('checklist');
    }

    public async loadMoreChildrenImpl(clearCache: boolean, context: IActionContext): Promise<AzExtTreeItem[]> {
        if (clearCache) {
            this._nextLink = undefined;
        }

        const registryTI = this.parent;

        const taskListResult: AcrModels.TaskListResult = this._nextLink === undefined ?
            await (await registryTI.getClient()).tasks.list(registryTI.resourceGroup, registryTI.registryName) :
            await (await registryTI.getClient()).tasks.listNext(this._nextLink);

        this._nextLink = taskListResult.nextLink;

        if (clearCache && taskListResult.length === 0) {
            return [new OpenUrlTreeItem(this, localize('vscode-docker.tree.registries.azure.learnBuildTask', 'Learn how to create a build task...'), 'https://aka.ms/acr/task')];
        } else {
            const result: AzExtTreeItem[] = await this.createTreeItemsWithErrorHandling(
                taskListResult,
                'invalidAzureTask',
                async t => new AzureTaskTreeItem(this, t),
                t => t.name
            );

            if (clearCache) {
                // If there are any runs _not_ associated with a task (e.g. the user ran a task from a local Dockerfile) add a tree item to display those runs
                if (await AzureTaskTreeItem.hasRunsWithoutTask(this.parent)) {
                    result.push(new AzureTaskTreeItem(this, undefined));
                }
            }

            return result;
        }
    }

    public hasMoreChildrenImpl(): boolean {
        return !!this._nextLink;
    }

    public isAncestorOfImpl(expectedContextValue: string | RegExp): boolean {
        if (expectedContextValue instanceof RegExp) {
            expectedContextValue = expectedContextValue.source.toString();
        }

        return expectedContextValue.toLowerCase().includes('task');
    }
}
