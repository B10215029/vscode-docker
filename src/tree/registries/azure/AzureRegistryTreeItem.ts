/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.md in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { ContainerRegistryManagementClient, ContainerRegistryManagementModels as AcrModels } from "@azure/arm-containerregistry"; // These are only dev-time imports so don't need to be lazy
import { URL } from "url";
import { AzExtTreeItem, createAzureClient, IActionContext } from "vscode-azureextensionui";
import { getResourceGroupFromId } from "../../../utils/azureUtils";
import { nonNullProp } from "../../../utils/nonNull";
import { getIconPath } from "../../getThemedIconPath";
import { azureOAuthProvider, IAzureOAuthContext } from "../auth/AzureOAuthProvider";
import { DockerV2RegistryTreeItemBase } from "../dockerV2/DockerV2RegistryTreeItemBase";
import { ICachedRegistryProvider } from "../ICachedRegistryProvider";
import { AzureRepositoryTreeItem } from "./AzureRepositoryTreeItem";
import { AzureTasksTreeItem } from "./AzureTasksTreeItem";
import { SubscriptionTreeItem } from "./SubscriptionTreeItem";

export class AzureRegistryTreeItem extends DockerV2RegistryTreeItemBase {
    public parent: SubscriptionTreeItem;

    protected authContext?: IAzureOAuthContext;

    private _tasksTreeItem: AzureTasksTreeItem;

    public constructor(parent: SubscriptionTreeItem, cachedProvider: ICachedRegistryProvider, private readonly registry: AcrModels.Registry) {
        super(parent, cachedProvider, azureOAuthProvider);
        this._tasksTreeItem = new AzureTasksTreeItem(this);
        this.authContext = {
            realm: new URL(`${this.baseUrl}/oauth2/token`),
            service: this.host,
            subscriptionContext: this.parent.root,
            scope: 'registry:catalog:*',
        };

        this.id = this.registryId;
        this.iconPath = getIconPath('azureRegistry');
    }

    public get registryName(): string {
        return nonNullProp(this.registry, 'name');
    }

    public get registryId(): string {
        return nonNullProp(this.registry, 'id');
    }

    public get resourceGroup(): string {
        return getResourceGroupFromId(this.registryId);
    }

    public get registryLocation(): string {
        return this.registry.location;
    }

    public async getClient(): Promise<ContainerRegistryManagementClient> {
        const armContainerRegistry = await import('@azure/arm-containerregistry');
        return createAzureClient(this.parent.root, armContainerRegistry.ContainerRegistryManagementClient);
    }

    public get label(): string {
        return this.registryName;
    }

    public get properties(): unknown {
        return this.registry;
    }

    public get baseUrl(): string {
        return `https://${nonNullProp(this.registry, 'loginServer')}`;
    }

    public createRepositoryTreeItem(name: string): AzureRepositoryTreeItem {
        return new AzureRepositoryTreeItem(this, name, this.cachedProvider, this.authHelper, this.authContext);
    }

    public async loadMoreChildrenImpl(clearCache: boolean, context: IActionContext): Promise<AzExtTreeItem[]> {
        const children: AzExtTreeItem[] = await super.loadMoreChildrenImpl(clearCache, context);
        if (clearCache) {
            children.push(this._tasksTreeItem);
        }
        return children;
    }

    public compareChildrenImpl(ti1: AzExtTreeItem, ti2: AzExtTreeItem): number {
        if (ti1 instanceof AzureTasksTreeItem) {
            return -1;
        } else if (ti2 instanceof AzureTasksTreeItem) {
            return 1;
        } else {
            return super.compareChildrenImpl(ti1, ti2);
        }
    }

    public async pickTreeItemImpl(expectedContextValues: (string | RegExp)[]): Promise<AzExtTreeItem | undefined> {
        if (expectedContextValues.some(v => this._tasksTreeItem.isAncestorOfImpl(v))) {
            return this._tasksTreeItem;
        } else {
            return undefined;
        }
    }

    public async deleteTreeItemImpl(): Promise<void> {
        await (await this.getClient()).registries.deleteMethod(this.resourceGroup, this.registryName);
    }

    public async tryGetAdminCredentials(): Promise<AcrModels.RegistryListCredentialsResult | undefined> {
        if (this.registry.adminUserEnabled) {
            return await (await this.getClient()).registries.listCredentials(this.resourceGroup, this.registryName);
        } else {
            return undefined;
        }
    }
}
