#pragma once

#include "win.h"


extern GUID zeroGuid;


// Identifier types for different WFP objects.
// WFP uses GUID for everything, so having separate types for these objects
// helps ensure that we know what type of object they refer to, prevents us from
// mixing them up, etc.  Most of the operations are different for different
// object types; in particular the "delete" functions are all separate.
//
// These are different from the FirewallFilter, Callout, and ProviderContext
// types; those are definitions for WFP objects that we can create - these
// represent actual WFP objects that have been created.
//
// In the future, these might provide object-specific operations (like "remove"
// or the "activate/deactivate" macros), but for now they just contain the
// identifiers.
class WfpFilterObject : public GUID {
public:
	WfpFilterObject(const GUID& srcGuid) {
		memcpy(this, &srcGuid, sizeof(GUID));
	}
};

class WfpCalloutObject : public GUID {
public:
	WfpCalloutObject(const GUID& srcGuid) {
		memcpy(this, &srcGuid, sizeof(GUID));
	}
};

class WfpProviderContextObject : public GUID {
public:
	WfpProviderContextObject(const GUID& srcGuid) {
		memcpy(this, &srcGuid, sizeof(GUID));
	}
};


class FirewallEngine
{
public:
	FirewallEngine();
	~FirewallEngine();

	bool open();

	bool installProvider();
	bool uninstallProvider();

	bool remove(const WfpFilterObject &filter);
	bool remove(const WfpCalloutObject &callout);
	bool remove(const WfpProviderContextObject &providerContext);

	bool removeAll();
	bool removeAll(const GUID& layerKey);

private:
	template<class ObjectT, class TemplateT, class CreateEnumHandleFuncT,
		class EnumFuncT, class DestroyEnumHandleFuncT,
		class ActionFuncT>
		bool enumObjects(const TemplateT &search,
			CreateEnumHandleFuncT createEnumHandleFunc,
			EnumFuncT enumFunc, DestroyEnumHandleFuncT destroyFunc,
			ActionFuncT actionFunc);

	template<class ActionFuncT>
	bool enumFilters(const GUID &layerKey, ActionFuncT actionFunc);
	bool removeFilters(const GUID& layerKey);
	template<class ActionFuncT>
	bool enumCallouts(const GUID &layerKey, ActionFuncT actionFunc);
	bool removeCallouts(const GUID& layerKey);

	template<class ActionFuncT>
	bool enumProviderContexts(ActionFuncT actionFunc);
	bool removeProviderContexts();

public:
	HANDLE _handle;
};

