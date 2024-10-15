import { createContext, PropsWithChildren, useContext, useEffect, useState } from "react";

interface IWristbandTenantContext {
    tenantId: string;
    tenantName: string;
    tenantLogo: string;
}

const WristbandTenantContext = createContext<IWristbandTenantContext>({
    tenantId: "unknown",
    tenantName: "unknown",
    tenantLogo: "", 
});

interface IOwnProps {
    tenants: { [tenantId: string]: { name: string, logo: string} };
}

function WristbandTenantProvider({ children, tenants }: PropsWithChildren<IOwnProps>) {
    const [tenantId, setTenantId] = useState("unknown");
    const [tenantName, setTenantName] = useState("unknown");
    const [tenantLogo, setTenantLogo] = useState("");
  
    useEffect(() => {
        const hostname = window.location.hostname;
        const tenantId = hostname.split(".")[0];
        const tenant = tenants[tenantId] || tenants["default"];
        if (!tenant) {
            setTenantId("unknown");
            setTenantName("unknown");
            setTenantLogo("");
            return;
        }
    
        setTenantId(tenantId);
        setTenantName(tenant.name);
        setTenantLogo(tenant.logo);
    }, [tenants]);
  
    return (
        <WristbandTenantContext.Provider value={{
            tenantId,
            tenantName,
            tenantLogo,
        }}>
            {children}
        </WristbandTenantContext.Provider>
    );
}

function useWristbandTenant() {
    const context = useContext(WristbandTenantContext);
    if (context === undefined) {
        throw new Error('useTenant must be used within a TenantProvider');
    }
    return context;
}

// eslint-disable-next-line react-refresh/only-export-components
export { WristbandTenantProvider, useWristbandTenant };
