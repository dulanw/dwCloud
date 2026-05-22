package types

import "encoding/xml"

// --------------------
// XML Structs for Nextcloud OCS
// --------------------

// OCSXML is used for XML responses like: <ocs><meta>...</meta><data>...</data></ocs>
type OCSXML[T any] struct {
	XMLName xml.Name `xml:"ocs"`
	Meta    Meta     `xml:"meta"`
	Data    T        `xml:"data"`
}

// OCSJSON is used for JSON responses like: {"ocs":{"meta":...,"data":...}}
type OCSJSON[T any] struct {
	OCS struct {
		Meta Meta `json:"meta"`
		Data T    `json:"data"`
	} `json:"ocs"`
}

func NewOCSJSON[T any](meta Meta, data T) OCSJSON[T] {
	var env OCSJSON[T]
	env.OCS.Meta = meta
	env.OCS.Data = data
	return env
}

func OKMeta(statusCode int) Meta {
	return Meta{
		Status:     "ok",
		StatusCode: statusCode,
		Message:    "OK",
	}
}

func FailMeta(statusCode int) Meta {
	return Meta{
		Status:     "failure",
		StatusCode: statusCode,
		Message:    "Invalid query, please check the syntax. API specifications are here: http://www.freedesktop.org/wiki/Specifications/open-collaboration-services.",
	}
}

type Meta struct {
	Status     string `xml:"status" json:"status"`
	StatusCode int    `xml:"statuscode" json:"statuscode"`
	Message    string `xml:"message" json:"message"`

	TotalItems   string `xml:"totalitems" json:"totalitems"`
	ItemsPerPage string `xml:"itemsperpage" json:"itemsperpage"`
}

type OCSCapabilitiesData struct {
	Version      Version      `xml:"version" json:"version"`
	Capabilities Capabilities `xml:"capabilities" json:"capabilities"`
}

type Version struct {
	Major           int    `xml:"major" json:"major"`
	Minor           int    `xml:"minor" json:"minor"`
	Micro           int    `xml:"micro" json:"micro"`
	String          string `xml:"string" json:"string"`
	Edition         string `xml:"edition" json:"edition"`
	ExtendedSupport string `xml:"extendedSupport" json:"extendedSupport"` // "" for false
}

type Capabilities struct {
	Bruteforce   Bruteforce   `xml:"bruteforce" json:"bruteforce"`
	DAV          DAV          `xml:"dav" json:"dav"`
	Files        Files        `xml:"files" json:"files"`
	Registration Registration `xml:"registration" json:"registration"`
	Theming      Theming      `xml:"theming" json:"theming"`
}

type Bruteforce struct {
	Delay       int    `xml:"delay" json:"delay"`
	AllowListed string `xml:"allow-listed" json:"allow-listed"` // "" for false
}

type DAV struct {
	AbsenceReplacement    bool   `xml:"absence-replacement" json:"absence-replacement"`
	AbsenceSupported      bool   `xml:"absence-supported" json:"absence-supported"`
	BulkUpload            string `xml:"bulkupload" json:"bulkupload"`
	Chunking              string `xml:"chunking" json:"chunking"`
	PublicSharingChunking bool   `xml:"public_sharing_chunking" json:"public_sharing_chunking"`
}

type Registration struct {
	Enabled  int    `xml:"enabled" json:"enabled"` // 1=true
	ApiRoot  string `xml:"apiRoot" json:"apiRoot"`
	ApiLevel string `xml:"apiLevel" json:"apiLevel"`
}

type Files struct {
	BlacklistedFiles            []string      `xml:"blacklisted_files>element" json:"blacklisted_files"`
	ForbiddenFilenames          []string      `xml:"forbidden_filenames>element" json:"forbidden_filenames"`
	ForbiddenFilenameBasenames  []string      `xml:"forbidden_filename_basenames>element" json:"forbidden_filename_basenames"`
	ForbiddenFilenameCharacters []string      `xml:"forbidden_filename_characters>element" json:"forbidden_filename_characters"`
	ForbiddenFilenameExtensions []string      `xml:"forbidden_filename_extensions>element" json:"forbidden_filename_extensions"`
	BigFileChunking             bool          `xml:"bigfilechunking" json:"bigfilechunking"`
	ChunkedUpload               ChunkedUpload `xml:"chunked_upload" json:"chunked_upload"`
	FileConversions             []interface{} `xml:"file_conversions" json:"file_conversions"`
	WindowsCompatibleFilenames  bool          `xml:"windows_compatible_filenames" json:"windows_compatible_filenames"`
	DirectEditing               DirectEditing `xml:"directEditing" json:"directEditing"`
	Comments                    bool          `xml:"comments" json:"comments"`
	Undelete                    bool          `xml:"undelete" json:"undelete"`
	DeleteFromTrash             bool          `xml:"delete_from_trash" json:"delete_from_trash"`
	Versioning                  bool          `xml:"versioning" json:"versioning"`
	VersionLabeling             bool          `xml:"version_labeling" json:"version_labeling"`
	VersionDeletion             bool          `xml:"version_deletion" json:"version_deletion"`
}

type ChunkedUpload struct {
	MaxSize          int `xml:"max_size" json:"max_size"`
	MaxParallelCount int `xml:"max_parallel_count" json:"max_parallel_count"`
}

type DirectEditing struct {
	URL            string `xml:"url" json:"url"`
	ETag           string `xml:"etag" json:"etag"`
	SupportsFileID bool   `xml:"supportsFileId" json:"supportsFileId"`
}

type Theming struct {
	Name              string `xml:"name" json:"name"`
	ProductName       string `xml:"productName" json:"productName"`
	URL               string `xml:"url" json:"url"`
	Slogan            string `xml:"slogan" json:"slogan"`
	Color             string `xml:"color" json:"color"`
	ColorText         string `xml:"color-text" json:"color-text"`
	ColorElement      string `xml:"color-element" json:"color-element"`
	ColorBright       string `xml:"color-element-bright" json:"color-element-bright"`
	ColorDark         string `xml:"color-element-dark" json:"color-element-dark"`
	Logo              string `xml:"logo" json:"logo"`
	Background        string `xml:"background" json:"background"`
	BackgroundText    string `xml:"background-text" json:"background-text"`
	BackgroundPlain   string `xml:"background-plain" json:"background-plain"`     // "" or "1"
	BackgroundDefault string `xml:"background-default" json:"background-default"` // "" or "1"
	LogoHeader        string `xml:"logoheader" json:"logoheader"`
	Favicon           string `xml:"favicon" json:"favicon"`
}

type OCSUserData struct {
	Enabled         bool   `json:"enabled" xml:"enabled"`
	StorageLocation string `json:"storageLocation" xml:"storageLocation"`

	ID string `json:"id" xml:"id"`

	FirstLoginTimestamp int64 `json:"firstLoginTimestamp" xml:"firstLoginTimestamp"`
	LastLoginTimestamp  int64 `json:"lastLoginTimestamp" xml:"lastLoginTimestamp"`
	LastLogin           int64 `json:"lastLogin" xml:"lastLogin"`

	Backend  string   `json:"backend" xml:"backend"`
	Subadmin []string `json:"subadmin" xml:"subadmin>element"`

	Quota   OCSUserQuota `json:"quota" xml:"quota"`
	Manager string       `json:"manager" xml:"manager"`

	AvatarScope string `json:"avatarScope" xml:"avatarScope"`

	Email      string `json:"email" xml:"email"`
	EmailScope string `json:"emailScope" xml:"emailScope"`

	AdditionalMail      []string `json:"additional_mail" xml:"additional_mail>element"`
	AdditionalMailScope []any    `json:"additional_mailScope" xml:"additional_mailScope>element"`

	DisplayName      string `json:"displayname" xml:"displayname"`
	DisplayNameDash  string `json:"display-name" xml:"display-name"`
	DisplayNameScope string `json:"displaynameScope" xml:"displaynameScope"`

	Phone      *string `json:"phone" xml:"phone"`
	PhoneScope *string `json:"phoneScope" xml:"phoneScope"`

	Address      *string `json:"address" xml:"address"`
	AddressScope *string `json:"addressScope" xml:"addressScope"`

	Website      *string `json:"website" xml:"website"`
	WebsiteScope *string `json:"websiteScope" xml:"websiteScope"`

	Twitter      *string `json:"twitter" xml:"twitter"`
	TwitterScope *string `json:"twitterScope" xml:"twitterScope"`

	Bluesky      *string `json:"bluesky" xml:"bluesky"`
	BlueskyScope *string `json:"blueskyScope" xml:"blueskyScope"`

	Fediverse      *string `json:"fediverse" xml:"fediverse"`
	FediverseScope *string `json:"fediverseScope" xml:"fediverseScope"`

	Organisation      *string `json:"organisation" xml:"organisation"`
	OrganisationScope *string `json:"organisationScope" xml:"organisationScope"`

	Role      string `json:"role" xml:"role"`
	RoleScope string `json:"roleScope" xml:"roleScope"`

	Headline      *string `json:"headline" xml:"headline"`
	HeadlineScope *string `json:"headlineScope" xml:"headlineScope"`

	Biography      *string `json:"biography" xml:"biography"`
	BiographyScope *string `json:"biographyScope" xml:"biographyScope"`

	ProfileEnabled      *string `json:"profile_enabled" xml:"profile_enabled"`
	ProfileEnabledScope *string `json:"profile_enabledScope" xml:"profile_enabledScope"`

	Pronouns      string `json:"pronouns" xml:"pronouns"`
	PronounsScope string `json:"pronounsScope" xml:"pronounsScope"`

	Groups   []string `json:"groups" xml:"groups>element"`
	Language string   `json:"language" xml:"language"`
	Locale   string   `json:"locale" xml:"locale"`
	Timezone string   `json:"timezone" xml:"timezone"`

	NotifyEmail *string `json:"notify_email" xml:"notify_email"`

	BackendCapabilities OCSUserBackendCapabilities `json:"backendCapabilities" xml:"backendCapabilities"`
}

type OCSUserQuota struct {
	Free     int64   `json:"free" xml:"free"`
	Used     int64   `json:"used" xml:"used"`
	Total    int64   `json:"total" xml:"total"`
	Relative float64 `json:"relative" xml:"relative"`
	Quota    int64   `json:"quota" xml:"quota"`
}

type OCSUserBackendCapabilities struct {
	SetDisplayName bool `json:"setDisplayName" xml:"setDisplayName"`
	SetPassword    bool `json:"setPassword" xml:"setPassword"`
}

type OCSUserStatusData struct {
	UserID              string  `json:"userId" xml:"userId"`
	Message             *string `json:"message" xml:"message"`
	MessageID           *string `json:"messageId" xml:"messageId"`
	MessageIsPredefined bool    `json:"messageIsPredefined" xml:"messageIsPredefined"`
	Icon                *string `json:"icon" xml:"icon"`
	ClearAt             *string `json:"clearAt" xml:"clearAt"`
	Status              string  `json:"status" xml:"status"`
	StatusIsUserDefined bool    `json:"statusIsUserDefined" xml:"statusIsUserDefined"`
}
