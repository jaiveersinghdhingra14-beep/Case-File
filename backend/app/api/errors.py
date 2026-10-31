from fastapi import HTTPException


class CaseFileException(HTTPException):
    def __init__(self, status_code: int, code: str, detail: str):
        super().__init__(status_code=status_code, detail={"code": code, "detail": detail})
        self.code = code
        self.custom_detail = detail


def not_found(detail: str = "Resource not found.") -> CaseFileException:
    return CaseFileException(status_code=404, code="not_found", detail=detail)


def wrong_state(detail: str) -> CaseFileException:
    return CaseFileException(status_code=409, code="wrong_state", detail=detail)


def dataset_not_ready(detail: str = "Dataset is not ready for querying.") -> CaseFileException:
    return CaseFileException(status_code=409, code="dataset_not_ready", detail=detail)


def no_ground_truth(detail: str = "No ground truth labels available for this dataset.") -> CaseFileException:
    return CaseFileException(status_code=409, code="no_ground_truth", detail=detail)


def already_in_progress(detail: str = "Operation is already in progress.") -> CaseFileException:
    return CaseFileException(status_code=409, code="already_in_progress", detail=detail)


def validation_error(detail: str) -> CaseFileException:
    return CaseFileException(status_code=422, code="validation_error", detail=detail)


def dataset_unreachable(detail: str = "Configured dataset path is unreachable.") -> CaseFileException:
    return CaseFileException(status_code=503, code="dataset_unreachable", detail=detail)


def llm_unreachable(detail: str = "LLM provider did not answer.") -> CaseFileException:
    return CaseFileException(status_code=503, code="llm_unreachable", detail=detail)
