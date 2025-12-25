# Category Checker Bot - Deso Decentralized Social

## Objective

This script is a bot designed to monitor the Deso blockchain for new posts and automatically classify their content (images or videos). Users can also register to receive notifications when posts containing specific categories are published.

## Key Features

* **Automatic Content Classification:** The bot analyzes new posts and classifies images and videos based on their content using a LLM.
* **User Notification System:**  Users can register to receive notifications when posts matching specific categories are published. Registration is done through a command embedded within a Deso post (e.g., "@CategoryChecker notify nature animals").
* **Periodic Reporting:** The bot periodically generates a report summarizing the frequency of different categories appearing in posts and shares it on the Deso blockchain.

## Prerequisites

* **Python 3.7+**
* **Dependencies:**  Install the required Python packages using `pip`:
