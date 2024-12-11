from dataclasses import dataclass


@dataclass
class SimpleResponse:
    number: int
    ip: str = ''
    time_in_ms: float = 0.0
    number_autonomous_system: int = 0
    verbose: bool = False
    not_answer: bool = False
    is_finished: bool = False

    def __str__(self) -> str:
        if self.not_answer:
            return f'{self.number} *'
        return f'{self.number} {self.ip} {self.time_in_ms} {self.number_autonomous_system if self.verbose else ""}'
