from uuid import UUID

from fastapi import APIRouter

from app.common.schemas import Envelope
from app.core.auth.deps import Auth
from app.core.files.dto.request.files import UploadUrlIn
from app.core.files.dto.response.files import (
    DownloadUrlOut,
    FileItemOut,
    FileOut,
    PresignedUpload,
    RemoveFileOut,
    UploadUrlOut,
)
from app.core.files.services import files as files_service
from app.database.session import Db
from app.locals import msg

router = APIRouter(prefix="/files", tags=["files"])


@router.post("/upload-url", status_code=201)
async def request_upload_url(body: UploadUrlIn, user: Auth, db: Db) -> Envelope[UploadUrlOut]:
    file, upload = await files_service.request_upload_url(
        db, user.sub, body.filename, body.content_type, body.size, body.visibility
    )
    data = UploadUrlOut(file=FileOut.model_validate(file), upload=PresignedUpload(**upload))
    return Envelope(status_code=201, message=msg.files.upload_url_created, data=data)


@router.post("/{id}/complete", status_code=201)
async def complete_upload(id: UUID, user: Auth, db: Db) -> Envelope[FileItemOut]:
    file = await files_service.complete_upload(db, user.sub, id)
    data = FileItemOut(file=FileOut.model_validate(file))
    return Envelope(status_code=201, message=msg.files.upload_confirmed, data=data)


@router.get("/{id}/download-url")
async def get_download_url(id: UUID, user: Auth, db: Db) -> Envelope[DownloadUrlOut]:
    data = DownloadUrlOut(**await files_service.download_url(db, user.sub, id))
    return Envelope(message=msg.files.download_url_created, data=data)


@router.get("")
async def list_files(user: Auth, db: Db) -> Envelope[list[FileOut]]:
    files = await files_service.list_files(db, user.sub)
    return Envelope(data=[FileOut.model_validate(f) for f in files])


@router.delete("/{id}")
async def delete_file(id: UUID, user: Auth, db: Db) -> Envelope[RemoveFileOut]:
    file_id = await files_service.delete_file(db, user.sub, id)
    return Envelope(message=msg.files.file_deleted, data=RemoveFileOut(id=file_id))
