# Category Checker Bot - Deso Decentralized Social

## Objective

This script is a bot designed to monitor the Deso blockchain for new posts and automatically classify their content (images or videos). Users can also register to receive notifications when posts containing specific categories are published.

## Key Features

* **Automatic Content Classification:** The bot analyzes new posts and classifies images and videos based on their content using a LLM.
* **User Notification System:**  Users can register to receive notifications when posts matching specific categories are published. Registration is done through a command embedded within a Deso post (e.g., "@CategoryChecker notify nature animals").
* **Periodic Reporting:** The bot periodically generates a report summarizing the frequency of different categories appearing in posts and shares it on the Deso blockchain.

# 🔔 Get Instant Alerts for Image, Video, and Text Posts

Never miss posts you care about. Subscribe to specific categories and get notified whenever a matching image, video, or text post is published. ⚠️ Disclaimer: The information and functionality described here are subject to change and are provided without any guarantees.

Use this single-line format to activate or deactivate notifications:

@CategoryChecker notify|stop image|video|text category

Examples to activate notifications:

@CategoryChecker notify video animals

Example to deactivate notifications:

@CategoryChecker stop image nature

Supported post types: image, video, text.

Available categories for image and video posts: people, nature, food, technology, vehicles, sports, art, text, holidays, abstract, trading, nsfw.

Available categories for text posts: scam, advertisements, politics, information, commentary, entertainment, technology, personal, other.




## Prerequisites

* **Python 3.7+**
* **Dependencies:**  Install the required Python packages using `pip`:
