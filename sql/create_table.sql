CREATE TABLE packages
(
	Id int NOT NULL UNIQUE AUTO_INCREMENT,
	Source int UNSIGNED,
	Destination int UNSIGNED,
	Typ tinyint UNSIGNED,
	Data BLOB
);

CREATE TABLE ipv4
(
	Id int NOT NULL UNIQUE,
	Version tinyint,
	HeaderLength tinyint,
	TypeOfService smallint,
	TotalLength int,
	Identification int,
	ForbidFragment bool,
	MoreFragments bool,
	FragmentOffset int,
	TimeToLive smallint,
	Protocol smallint UNSIGNED,
	HeaderChecksum int,
	Source int UNSIGNED,
	Destination int UNSIGNED,
);
