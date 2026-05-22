package types

import (
	"encoding/xml"
)

//
// ----------------------------------------------------
// BASIC WEBDAV (PROPFIND only)
// ----------------------------------------------------
//

type WebDAVMultiStatus struct {
	XMLName xml.Name `xml:"d:multistatus"`

	XmlnsD  string `xml:"xmlns:d,attr"`
	XmlnsS  string `xml:"xmlns:s,attr"`
	XmlnsOC string `xml:"xmlns:oc,attr"`
	XmlnsNC string `xml:"xmlns:nc,attr"`

	Responses []WebDAVResponse `xml:"d:response"`
}

type WebDAVResponse struct {
	Href     string           `xml:"d:href"`
	Propstat []WebDAVPropstat `xml:"d:propstat"`
}

type WebDAVPropstat struct {
	// Important: allow either OK props or Missing props to live under <d:prop>.
	Prop   any    `xml:"d:prop"`
	Status string `xml:"d:status"`
}

type WebDAVDeadProperty struct {
	XMLName  xml.Name
	InnerXML string `xml:",innerxml"`
}

type WebDAVChecksums struct {
	Checksums []string `xml:"oc:checksum,omitempty"`
}

/*
	WebDAVResourceType

For a directory (collection), servers return:
<d:resourcetype>

	<d:collection/>

</d:resourcetype>

For a **file (non-collection)**, they typically return an _empty_ element:
<d:resourcetype/>
*/
type WebDAVResourceType struct {
	Collection *struct{} `xml:"d:collection,omitempty"`
}

/*
WebDAVPropOK
WebDAVPropNotFound

		For each response, we return the properties that we have with status 200, and also the ones that we haven't found
		with status 404, so we don't want to just ommit it if we don't have it.
	 <d:response>
	        <d:href>/remote.php/dav/files/admin/</d:href>
	        <d:propstat>
	            <d:prop>
	                <d:resourcetype>
	                    <d:collection />
	                </d:resourcetype>
	                <d:getlastmodified>Wed, 18 Feb 2026 20:24:02 GMT</d:getlastmodified>
	                <d:getetag>&quot;69961fe2b5a10&quot;</d:getetag>
	                <d:quota-available-bytes>1099455468099</d:quota-available-bytes>
	                <d:quota-used-bytes>56159677</d:quota-used-bytes>
	                <oc:size>67</oc:size>
	                <oc:id>00000002ocwjlk8i6jeb</oc:id>
	                <oc:fileid>2</oc:fileid>
	                <oc:permissions>GDNVCK</oc:permissions>
	                <nc:share-attributes>[]</nc:share-attributes>
	                <oc:data-fingerprint></oc:data-fingerprint>
	                <oc:share-types />
	                <nc:is-mount-root>false</nc:is-mount-root>
	            </d:prop>
	            <d:status>HTTP/1.1 200 OK</d:status>
	        </d:propstat>
	        <d:propstat>
	            <d:prop>
	                <d:getcontentlength />
	                <oc:downloadURL />
	                <oc:dDC />
	                <oc:checksums />
	                <nc:is-encrypted />
	                <nc:metadata-files-live-photo />
	            </d:prop>
	            <d:status>HTTP/1.1 404 Not Found</d:status>
	        </d:propstat>
	    </d:response>
*/
type WebDAVPropOK struct {
	ResourceType  *WebDAVResourceType `xml:"d:resourcetype,omitempty"`
	LastModified  string              `xml:"d:getlastmodified,omitempty"`
	ContentLength *string             `xml:"d:getcontentlength,omitempty"`
	ContentType   string              `xml:"d:getcontenttype,omitempty"`
	ETag          string              `xml:"d:getetag,omitempty"`

	QuotaAvailableBytes *string `xml:"d:quota-available-bytes,omitempty"`
	QuotaUsedBytes      *string `xml:"d:quota-used-bytes,omitempty"`

	OCSize             string           `xml:"oc:size,omitempty"`
	OCID               string           `xml:"oc:id,omitempty"`
	OCFileID           string           `xml:"oc:fileid,omitempty"`
	OCDownloadURL      *string          `xml:"oc:downloadURL,omitempty"`
	OCPermissions      string           `xml:"oc:permissions,omitempty"`
	OCFavorite         *int             `xml:"oc:favorite,omitempty"`
	OCCommentsUnread   *int             `xml:"oc:comments-unread,omitempty"`
	OCOwnerID          string           `xml:"oc:owner-id,omitempty"`
	OCOwnerDisplayName string           `xml:"oc:owner-display-name,omitempty"`
	OCChecksums        *WebDAVChecksums `xml:"oc:checksums,omitempty"`

	// Nextcloud extensions
	NCHasPreview             *bool  `xml:"nc:has-preview,omitempty"`
	NCContainedFolderCount   *int   `xml:"nc:contained-folder-count,omitempty"`
	NCContainedFileCount     *int   `xml:"nc:contained-file-count,omitempty"`
	NCIsEncrypted            string `xml:"nc:is-encrypted,omitempty"`
	NCMetadataFilesLivePhoto *bool  `xml:"nc:metadata-files-live-photo,omitempty"`
	NCShareAttributes        string `xml:"nc:share-attributes,omitempty"`
	NCIsMountRoot            *bool  `xml:"nc:is-mount-root"` // must be present (your samples show false)

	// ownCloud extensions
	OCDDC             *struct{} `xml:"oc:dDC,omitempty"`
	OCDataFingerprint string    `xml:"oc:data-fingerprint,omitempty"`
	OCShareTypes      *struct{} `xml:"oc:share-types,omitempty"`

	// Dead properties — emitted directly inline using each item's own XMLName.
	DeadProperties []WebDAVDeadProperty `xml:",any"`
}

type WebDAVPropNotFound struct {
	//ResourceType  *struct{} `xml:"d:resourcetype,omitempty"`
	//LastModified  *struct{} `xml:"d:getlastmodified,omitempty"`
	ContentLength *struct{} `xml:"d:getcontentlength,omitempty"`
	//ETag          *struct{} `xml:"d:getetag,omitempty"`

	QuotaAvailableBytes *struct{} `xml:"d:quota-available-bytes,omitempty"`
	QuotaUsedBytes      *struct{} `xml:"d:quota-used-bytes,omitempty"`

	//OCSize   *struct{} `xml:"oc:size,omitempty"`
	//OCID     *struct{} `xml:"oc:id,omitempty"`
	//OCFileID *struct{} `xml:"oc:fileid,omitempty"`

	OCDownloadURL *struct{} `xml:"oc:downloadURL,omitempty"`
	OCDDC         *struct{} `xml:"oc:dDC,omitempty"`
	//OCPermissions *struct{} `xml:"oc:permissions,omitempty"`
	OCChecksums *struct{} `xml:"oc:checksums,omitempty"`

	NCIsEncrypted            *struct{} `xml:"nc:is-encrypted,omitempty"`
	NCMetadataFilesLivePhoto *struct{} `xml:"nc:metadata-files-live-photo,omitempty"`
	//NCShareAttributes        *struct{} `xml:"nc:share-attributes,omitempty"`
	//OCDataFingerprint        *struct{} `xml:"oc:data-fingerprint,omitempty"`
	//OCShareTypes             *struct{} `xml:"oc:share-types,omitempty"`
	//NCIsMountRoot            *struct{} `xml:"nc:is-mount-root,omitempty"`

	DeadProperties []WebDAVDeadProperty `xml:",any"`
}
