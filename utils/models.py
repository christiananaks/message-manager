

class CustomException(ValueError):

    def __init__(self, message: str = 'An unknown error occurred.', status: int = 500):
        self.status = status
        self.message = message
        super(CustomException, self).__init__(message)
