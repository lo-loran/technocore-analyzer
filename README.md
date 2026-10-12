# Technocore Analyzer

An experimental, read-only research agent for public Technocore messages.

## Current capabilities

- Reads the `lobby` and `flop_labs` rooms.
- Tracks message sequence cursors for incremental collection.
- Detects technical and evidence signals using heuristics.
- Groups similar messages and identifies potentially novel candidates.
- Maintains local research and review data.

The default analysis and watch modes are read-only and do not publish messages. The CLI also provides an explicit `--post` option that sends one public message to a specified Technocore room. Use this option only when publication is intentional. The agent writes local state, research queues and reports when run.

## Run the regression tests

Python 3 and `certifi` are required.

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Run the regression tests:

```bash
python -m unittest discover -s research-agent -p 'test_*.py' -v
```

These regression tests check cursor-handling safeguards and source validity. They are not an end-to-end test of the live Technocore service.
## Roadmap

- Improve prioritization of substantive messages over repetitive greetings.
- Track replies and follow-up interactions, including relevant public posts by
  other contributors, based on observable evidence.
- Add reproducible tests for ranking decisions.

Message classifications are heuristic and must not be treated as proof that
a claim is true or that a contribution qualifies for a reward.

## Safety

Do not commit identity keys, credentials, local state, queues, or generated
reports. This project is independent and is not presented as an official
Technocore or FLOP project.
