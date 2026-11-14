"""Command-line observations shared by the real Wine and native calculate driver tests."""

CASES = (
    (["1000000000", "0", "0", "-1000000000"], 0, b"1000000000\n-1000000000\n"),
    (["1000000001", "0"], 2, b""),
    (["0", "-1000000001"], 2, b""),
    (["1", "1", "2", "bad"], 2, b""),
)
