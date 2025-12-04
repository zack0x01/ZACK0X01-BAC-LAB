# YouTube Video IDs Configuration

To use your actual zack0X01 YouTube videos, replace the placeholder video IDs in `app.py`:

1. Open `app.py`
2. Find the `get_course_videos()` function (around line 410)
3. Replace the `youtube_id` values with your actual video IDs

Example:
```python
videos = [
    {
        'id': 1,
        'title': 'Bug Bounty Basics - Getting Started',
        'youtube_id': 'abc123xyz',  # Replace with actual video ID from zack0X01 channel
        'description': 'Learn the fundamentals of bug bounty hunting'
    },
    # ... more videos
]
```

## How to get YouTube Video IDs:

1. Go to your YouTube video
2. Copy the URL: `https://www.youtube.com/watch?v=VIDEO_ID_HERE`
3. The part after `v=` is your video ID

## Example URLs:
- Full URL: `https://www.youtube.com/watch?v=dQw4w9WgXcQ`
- Video ID: `dQw4w9WgXcQ`

Replace `YOUR_VIDEO_ID_1`, `YOUR_VIDEO_ID_2`, etc. with your actual video IDs from the zack0X01 channel.

